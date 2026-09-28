"""Phase 2 temporary token based bridging.

This module does not create or register devices.

A device must first complete Phase 1 authentication and registration.
Phase 1 stores the verified DID, public key, metadata and leaf in the
current registration batch.

Phase 2 retrieves that trusted Phase 1 record and issues a short lived
fog signed credential while the device waits for permanent Merkle
inclusion.

The parent simulator controls device arrival times, epochs,
registration cutoff and batch finalization.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .provisional_access import authorize


class TokenError(ValueError):
    """Raised when temporary token issuance cannot proceed."""


class TokenService:
    """Manage Phase 2 temporary credentials and provisional access."""

    def __init__(
        self,
        connection,
        fog_private_key=None,
        lifetime_seconds: int = 300,
    ):
        self.connection = connection
        self.lifetime_seconds = lifetime_seconds

        # Fog signing key for temporary credentials.
        if fog_private_key is None:
            self.fog_private_key = ec.generate_private_key(
                ec.SECP256R1()
            )
        else:
            self.fog_private_key = fog_private_key

        self.fog_public_key = self.fog_private_key.public_key()

        self._create_security_tables()

    # =========================================================
    # DATABASE
    # =========================================================

    def _create_security_tables(self) -> None:
        """Create Phase 2 security and revocation state."""

        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                used_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revoked_tokens (
                token_id TEXT PRIMARY KEY,
                revoked_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revoked_devices (
                did TEXT PRIMARY KEY,
                revoked_at REAL NOT NULL,
                reason TEXT
            );
            """
        )

        self.connection.commit()

    # =========================================================
    # ENCODING HELPERS
    # =========================================================

    @staticmethod
    def _encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(
            data
        ).decode(
            "ascii"
        ).rstrip("=")

    @staticmethod
    def _decode(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)

        return base64.urlsafe_b64decode(
            value + padding
        )

    @staticmethod
    def _encode_json(data: dict) -> str:
        raw = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return TokenService._encode(raw)

    @staticmethod
    def _decode_json(value: str) -> dict:
        raw = TokenService._decode(value)

        return json.loads(
            raw.decode("utf-8")
        )

    # =========================================================
    # PHASE 1 CONNECTION
    # =========================================================

    def get_pending_device(self, did: str):
        """
        Retrieve a device already authenticated and queued by Phase 1.

        Phase 2 does not create or register another device.

        This connects Phase 1 and Phase 2 using the same database
        record, DID and public key.
        """

        row = self.connection.execute(
            """
            SELECT
                ol.did,
                ol.public_key,
                ol.metadata,
                ol.batch_id,
                b.status
            FROM open_leaves AS ol
            JOIN batches AS b
                ON ol.batch_id = b.batch_id
            WHERE ol.did = ?
            """,
            (did,),
        ).fetchone()

        if row is None:
            raise TokenError(
                "device has not completed Phase 1 registration"
            )

        if row["status"] != "open":
            raise TokenError(
                "device is not waiting in an open registration batch"
            )

        return row

    # Compatibility with earlier code.
    def _get_pending_device(self, did: str):
        return self.get_pending_device(did)

    # =========================================================
    # DEVICE REVOCATION STATUS
    # =========================================================

    def is_device_revoked(self, did: str) -> bool:
        """Check whether the device has been revoked at fog level."""

        row = self.connection.execute(
            """
            SELECT 1
            FROM revoked_devices
            WHERE did = ?
            """,
            (did,),
        ).fetchone()

        return row is not None

    # =========================================================
    # PERMANENT INCLUSION STATUS
    # =========================================================

    def has_permanent_inclusion(self, did: str) -> bool:
        """
        Return True once a permanent Merkle inclusion proof exists.

        Once permanent inclusion exists, Phase 2 provisional bridging
        is no longer required.
        """

        row = self.connection.execute(
            """
            SELECT 1
            FROM proofs AS p
            JOIN batches AS b
                ON b.epoch_id = p.epoch_id
            WHERE p.did = ?
              AND b.status = 'closed'
            """,
            (did,),
        ).fetchone()

        return row is not None

    # =========================================================
    # TOKEN ISSUANCE
    # =========================================================

    def issue_token(
        self,
        did: str,
        lifetime_seconds: int | None = None,
    ) -> str:
        """
        Issue a temporary credential for a Phase 1 registered device.

        DID is supplied by the simulator.

        Public key, metadata, role and batch information are retrieved
        from the existing Phase 1 registration record.
        """

        # -----------------------------------------------------
        # DEVICE REVOCATION CHECK
        # -----------------------------------------------------

        if self.is_device_revoked(did):
            raise TokenError(
                "device is revoked and cannot receive "
                "a temporary token"
            )

        # -----------------------------------------------------
        # PERMANENT MEMBERSHIP CHECK
        # -----------------------------------------------------

        if self.has_permanent_inclusion(did):
            raise TokenError(
                "device already has a permanent inclusion proof; "
                "use Phase 3 normal verification instead of "
                "Phase 2 bridging"
            )

        # -----------------------------------------------------
        # RETRIEVE EXISTING PHASE 1 IDENTITY
        # -----------------------------------------------------

        row = self.get_pending_device(did)

        public_key_bytes = bytes(
            row["public_key"]
        )

        metadata = json.loads(
            row["metadata"]
        )

        role = metadata.get(
            "device_type",
            "unknown",
        )

        batch_id = row["batch_id"]

        # -----------------------------------------------------
        # TOKEN LIFETIME
        # -----------------------------------------------------

        lifetime = (
            lifetime_seconds
            if lifetime_seconds is not None
            else self.lifetime_seconds
        )

        if lifetime <= 0:
            raise TokenError(
                "temporary token lifetime must be "
                "greater than zero"
            )

        now = int(time.time())
        expiry = now + lifetime

        token_id = str(uuid.uuid4())

        # -----------------------------------------------------
        # TOKEN PAYLOAD
        # -----------------------------------------------------

        payload = {
            "token_id": token_id,
            "did": did,
            "public_key": self._encode(
                public_key_bytes
            ),
            "metadata": metadata,
            "role": role,
            "batch_id": batch_id,
            "issued_at": now,
            "expiry": expiry,
            "state": "provisional",
        }

        encoded_payload = self._encode_json(
            payload
        )

        # -----------------------------------------------------
        # FOG SIGNATURE
        # -----------------------------------------------------

        signature = self.fog_private_key.sign(
            encoded_payload.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )

        encoded_signature = self._encode(
            signature
        )

        token = (
            f"{encoded_payload}."
            f"{encoded_signature}"
        )

        print(
            f"[TOKEN_ISSUE] "
            f"did={did} "
            f"role={role} "
            f"batch={batch_id} "
            f"expires_in={lifetime}s "
            f"state=provisional"
        )

        return token

    # =========================================================
    # TOKEN VERIFICATION
    # =========================================================

    def verify_token(
        self,
        token: str,
    ) -> tuple[bool, dict | None, str]:
        """
        Verify temporary token.

        Checks:
            fog signature
            expiry
            token revocation
            device revocation
            permanent inclusion status
            Phase 1 pending registration
            public key binding
            batch binding
        """

        # -----------------------------------------------------
        # SPLIT TOKEN
        # -----------------------------------------------------

        try:
            encoded_payload, encoded_signature = (
                token.split(".", 1)
            )

        except ValueError:
            return (
                False,
                None,
                "malformed temporary token",
            )

        # -----------------------------------------------------
        # VERIFY FOG SIGNATURE
        # -----------------------------------------------------

        try:
            signature = self._decode(
                encoded_signature
            )

            self.fog_public_key.verify(
                signature,
                encoded_payload.encode("utf-8"),
                ec.ECDSA(hashes.SHA256()),
            )

        except (
            InvalidSignature,
            ValueError,
            TypeError,
        ):
            return (
                False,
                None,
                "temporary token signature is invalid",
            )

        # -----------------------------------------------------
        # DECODE PAYLOAD
        # -----------------------------------------------------

        try:
            payload = self._decode_json(
                encoded_payload
            )

        except (
            ValueError,
            TypeError,
            json.JSONDecodeError,
        ):
            return (
                False,
                None,
                "temporary token payload is invalid",
            )

        # -----------------------------------------------------
        # EXPIRY
        # -----------------------------------------------------

        expiry = payload.get(
            "expiry"
        )

        if expiry is None:
            return (
                False,
                payload,
                "temporary token has no expiry",
            )

        if time.time() >= expiry:
            return (
                False,
                payload,
                "temporary token has expired",
            )

        # -----------------------------------------------------
        # TOKEN ID
        # -----------------------------------------------------

        token_id = payload.get(
            "token_id"
        )

        if not token_id:
            return (
                False,
                payload,
                "temporary token has no token id",
            )

        # -----------------------------------------------------
        # TOKEN REVOCATION
        # -----------------------------------------------------

        revoked = self.connection.execute(
            """
            SELECT 1
            FROM revoked_tokens
            WHERE token_id = ?
            """,
            (token_id,),
        ).fetchone()

        if revoked is not None:
            return (
                False,
                payload,
                "temporary token has been revoked",
            )

        # -----------------------------------------------------
        # DID
        # -----------------------------------------------------

        did = payload.get(
            "did"
        )

        if not did:
            return (
                False,
                payload,
                "temporary token has no DID",
            )

        # -----------------------------------------------------
        # DEVICE REVOCATION
        # -----------------------------------------------------

        if self.is_device_revoked(did):
            return (
                False,
                payload,
                "device has been revoked since "
                "token issuance",
            )

        # -----------------------------------------------------
        # PERMANENT MEMBERSHIP
        # -----------------------------------------------------

        if self.has_permanent_inclusion(did):
            return (
                False,
                payload,
                "device now has permanent inclusion; "
                "provisional token is stale",
            )

        # -----------------------------------------------------
        # VERIFY DEVICE STILL BELONGS TO OPEN PHASE 1 BATCH
        # -----------------------------------------------------

        try:
            pending = self.get_pending_device(
                did
            )

        except TokenError:
            return (
                False,
                payload,
                "device is no longer waiting in "
                "an open batch",
            )

        # -----------------------------------------------------
        # PUBLIC KEY BINDING
        # -----------------------------------------------------

        stored_public_key = bytes(
            pending["public_key"]
        )

        token_public_key = payload.get(
            "public_key"
        )

        if token_public_key != self._encode(
            stored_public_key
        ):
            return (
                False,
                payload,
                "token public key does not match "
                "Phase 1 record",
            )

        # -----------------------------------------------------
        # BATCH BINDING
        # -----------------------------------------------------

        if (
            payload.get("batch_id")
            != pending["batch_id"]
        ):
            return (
                False,
                payload,
                "temporary token batch does not match "
                "Phase 1 record",
            )

        return (
            True,
            payload,
            "temporary token valid",
        )

    # =========================================================
    # NONCE
    # =========================================================

    @staticmethod
    def create_nonce() -> str:
        """Generate a fresh nonce for one resource request."""

        return secrets.token_hex(16)

    def check_and_use_nonce(
        self,
        nonce: str,
    ) -> tuple[bool, str]:
        """Reject a nonce if it has already been used."""

        if not nonce:
            return (
                False,
                "nonce missing",
            )

        existing = self.connection.execute(
            """
            SELECT 1
            FROM used_nonces
            WHERE nonce = ?
            """,
            (nonce,),
        ).fetchone()

        if existing is not None:
            return (
                False,
                "replay attack detected: "
                "nonce already used",
            )

        self.connection.execute(
            """
            INSERT INTO used_nonces
            (nonce, used_at)
            VALUES (?, ?)
            """,
            (
                nonce,
                time.time(),
            ),
        )

        self.connection.commit()

        return (
            True,
            "nonce accepted",
        )

    # =========================================================
    # DEVICE PROOF OF POSSESSION
    # =========================================================

    def verify_device_signature(
        self,
        payload: dict,
        nonce: str,
        signature: bytes,
    ) -> tuple[bool, str]:
        """
        Verify that the requester possesses the private key
        corresponding to the Phase 1 public key.
        """

        try:
            public_key_bytes = self._decode(
                payload["public_key"]
            )

            public_key = (
                serialization.load_der_public_key(
                    public_key_bytes
                )
            )

            if not isinstance(
                public_key,
                ec.EllipticCurvePublicKey,
            ):
                return (
                    False,
                    "device public key is invalid",
                )

            if not isinstance(
                public_key.curve,
                ec.SECP256R1,
            ):
                return (
                    False,
                    "device public key must use P-256",
                )

            public_key.verify(
                signature,
                nonce.encode("utf-8"),
                ec.ECDSA(hashes.SHA256()),
            )

        except (
            KeyError,
            ValueError,
            TypeError,
            InvalidSignature,
        ):
            return (
                False,
                "device proof-of-possession failed",
            )

        return (
            True,
            "device proof-of-possession verified",
        )

    # =========================================================
    # PROVISIONAL RESOURCE REQUEST
    # =========================================================

    def request_resource(
        self,
        token: str,
        nonce: str,
        device_signature: bytes,
        resource: str,
        operation: str,
    ) -> bool:
        """
        Validate a Phase 2 provisional resource request.

        Checks:

            1. Fog token signature
            2. Token expiry
            3. Token revocation
            4. Device revocation
            5. Phase 1 pending registration
            6. Public key binding
            7. Fresh nonce
            8. Device proof of possession
            9. Limited Phase 2 provisional policy
        """

        # -----------------------------------------------------
        # TOKEN CHECKS
        # -----------------------------------------------------

        valid, payload, reason = (
            self.verify_token(
                token
            )
        )

        if not valid:
            print(
                f"[TEMP_ACCESS] "
                f"resource={resource} "
                f"operation={operation} "
                f"decision=DENY "
                f"reason={reason}"
            )

            return False

        # -----------------------------------------------------
        # NONCE CHECK
        # -----------------------------------------------------

        nonce_ok, nonce_reason = (
            self.check_and_use_nonce(
                nonce
            )
        )

        if not nonce_ok:
            print(
                f"[TEMP_ACCESS] "
                f"resource={resource} "
                f"operation={operation} "
                f"decision=DENY "
                f"reason={nonce_reason}"
            )

            return False

        # -----------------------------------------------------
        # DEVICE PROOF OF POSSESSION
        # -----------------------------------------------------

        pop_ok, pop_reason = (
            self.verify_device_signature(
                payload,
                nonce,
                device_signature,
            )
        )

        if not pop_ok:
            print(
                f"[TEMP_ACCESS] "
                f"resource={resource} "
                f"operation={operation} "
                f"decision=DENY "
                f"reason={pop_reason}"
            )

            return False

        # -----------------------------------------------------
        # LIMITED PHASE 2 POLICY
        # -----------------------------------------------------

        role = payload.get(
            "role",
            "unknown",
        )

        allowed, policy_reason = authorize(
            role,
            resource,
            operation,
        )

        if not allowed:
            print(
                f"[TEMP_ACCESS] "
                f"did={payload.get('did')} "
                f"resource={resource} "
                f"operation={operation} "
                f"decision=DENY "
                f"reason={policy_reason}"
            )

            return False

        print(
            f"[TEMP_ACCESS] "
            f"did={payload.get('did')} "
            f"resource={resource} "
            f"operation={operation} "
            f"nonce=fresh "
            f"decision=ALLOW"
        )

        return True

    # =========================================================
    # TOKEN REVOCATION
    # =========================================================

    def revoke_token(
        self,
        token: str,
    ) -> bool:
        """Immediately revoke one Phase 2 temporary credential."""

        try:
            encoded_payload, _ = token.split(
                ".",
                1,
            )

            payload = self._decode_json(
                encoded_payload
            )

            token_id = payload.get(
                "token_id"
            )

            did = payload.get(
                "did"
            )

            if not token_id:
                return False

            self.connection.execute(
                """
                INSERT OR IGNORE INTO revoked_tokens
                (token_id, revoked_at)
                VALUES (?, ?)
                """,
                (
                    token_id,
                    time.time(),
                ),
            )

            self.connection.commit()

            print(
                f"[TOKEN_REVOKE] "
                f"did={did} "
                f"result=revoked"
            )

            return True

        except (
            ValueError,
            TypeError,
            json.JSONDecodeError,
        ):
            return False

    # =========================================================
    # DEVICE REVOCATION
    # =========================================================

    def revoke_device(
        self,
        did: str,
        reason: str = "device revoked by fog",
    ) -> bool:
        """
        Revoke the device itself.

        This is different from revoke_token().

        Token revocation invalidates one temporary credential.

        Device revocation marks the DID as revoked so new temporary
        credentials cannot be issued and existing temporary
        credentials are rejected.
        """

        self.connection.execute(
            """
            INSERT OR REPLACE INTO revoked_devices
            (did, revoked_at, reason)
            VALUES (?, ?, ?)
            """,
            (
                did,
                time.time(),
                reason,
            ),
        )

        self.connection.commit()

        print(
            f"[DEVICE_REVOKE] "
            f"did={did} "
            f"result=revoked"
        )

        return True