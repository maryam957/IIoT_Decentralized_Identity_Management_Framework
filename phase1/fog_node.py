"""Fog node registration, batching, anchoring, and the public Phase 1 API."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .merkle import build_tree

DEFAULT_PSK = "iiot-demo-psk"


class RegistrationError(ValueError):
    """Raised when authentication or proof-of-possession fails."""


@dataclass(frozen=True)
class RegistrationResult:
    did: str
    leaf_hash: str
    batch_id: str


@dataclass(frozen=True)
class InclusionProof:
    did: str
    epoch_id: int
    leaf_hash: str
    proof: list[dict[str, str]]


@dataclass(frozen=True)
class BatchResult:
    batch_id: str
    epoch_id: int
    root: str
    proofs: dict[str, InclusionProof]


def _leaf_hash(did: str, public_key_bytes: bytes) -> bytes:
    # Contract: DID is UTF-8; public key is DER SubjectPublicKeyInfo; no delimiter.
    return hashlib.sha256(
        did.encode("utf-8") + public_key_bytes
    ).digest()


class FogNode:
    def __init__(
        self,
        psk: str = DEFAULT_PSK,
        db_path: str = ":memory:",
    ):
        self.psk = psk
        self.connection = sqlite3.connect(db_path)
        self.connection.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self):
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS batches (
                batch_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                epoch_id INTEGER,
                root TEXT,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS open_leaves (
                batch_id TEXT NOT NULL,
                did TEXT PRIMARY KEY,
                leaf_hash BLOB NOT NULL,
                public_key BLOB NOT NULL,
                metadata TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS anchors (
                epoch_id INTEGER PRIMARY KEY,
                batch_id TEXT NOT NULL,
                root TEXT NOT NULL,
                prev_hash TEXT,
                timestamp REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proofs (
                epoch_id INTEGER NOT NULL,
                did TEXT NOT NULL,
                leaf_hash TEXT NOT NULL,
                proof TEXT NOT NULL,
                PRIMARY KEY (epoch_id, did)
            );
            """
        )

        if (
            self.connection.execute(
                "SELECT 1 FROM batches LIMIT 1"
            ).fetchone()
            is None
        ):
            self.connection.execute(
                "INSERT INTO batches VALUES (?, 'open', NULL, NULL, ?)",
                ("open-1", time.time()),
            )
            self.connection.commit()

    def authenticate(self, psk: str) -> None:
        # A real deployment would place TLS or another authenticated transport here.
        if not secrets.compare_digest(psk, self.psk):
            raise RegistrationError(
                "protected connection authentication failed"
            )

    def create_challenge(self, did: str) -> bytes:
        del did
        return secrets.token_bytes(32)

    def register_device(
        self,
        psk: str,
        did: str,
        public_key_bytes: bytes,
        metadata: dict,
        *,
        challenge: bytes | None = None,
        signature: bytes | None = None,
    ) -> RegistrationResult:

        self.authenticate(psk)

        if challenge is None or signature is None:
            raise RegistrationError(
                "a fresh challenge and signature are required"
            )

        try:
            public_key = serialization.load_der_public_key(
                public_key_bytes
            )

            if (
                not isinstance(
                    public_key,
                    ec.EllipticCurvePublicKey,
                )
                or not isinstance(
                    public_key.curve,
                    ec.SECP256R1,
                )
            ):
                raise RegistrationError(
                    "public key must use P-256"
                )

            public_key.verify(
                signature,
                challenge,
                ec.ECDSA(hashes.SHA256()),
            )

        except (
            ValueError,
            TypeError,
            InvalidSignature,
        ) as error:

            raise RegistrationError(
                "proof-of-possession verification failed"
            ) from error

        row = self.connection.execute(
            """
            SELECT batch_id
            FROM batches
            WHERE status = 'open'
            ORDER BY created_at DESC
            LIMIT 1
            """
        ).fetchone()

        batch_id = row["batch_id"]

        leaf = _leaf_hash(
            did,
            public_key_bytes,
        )

        try:
            self.connection.execute(
                "INSERT INTO open_leaves VALUES (?, ?, ?, ?, ?)",
                (
                    batch_id,
                    did,
                    leaf,
                    public_key_bytes,
                    json.dumps(
                        metadata,
                        sort_keys=True,
                    ),
                ),
            )

            self.connection.commit()

        except sqlite3.IntegrityError as error:

            raise RegistrationError(
                f"device is already registered: {did}"
            ) from error

        result = RegistrationResult(
            did,
            leaf.hex(),
            batch_id,
        )

        print(
            f"[REGISTER] did={did} "
            f"leaf={result.leaf_hash} "
            f"batch=open"
        )

        return result

    def exclude_revoked_device(self, did: str) -> bool:
        """Remove a revoked pending device from the active batch."""

        row = self.connection.execute(
            """
            SELECT did
            FROM open_leaves
            WHERE did = ?
            """,
            (did,),
        ).fetchone()

        if row is None:
            return False

        self.connection.execute(
            """
            DELETE FROM open_leaves
            WHERE did = ?
            """,
            (did,),
        )

        self.connection.commit()

        print(
            "[REVOCATION] did=",
            did,
            "result=excluded_from_active_batch",
        )

        return True

    def close_batch(
        self,
        batch_id: str,
    ) -> BatchResult:

        row = self.connection.execute(
            """
            SELECT status
            FROM batches
            WHERE batch_id = ?
            """,
            (batch_id,),
        ).fetchone()

        if row is None or row["status"] != "open":
            raise ValueError(
                f"open batch not found: {batch_id}"
            )

        rows = self.connection.execute(
            """
            SELECT did, leaf_hash
            FROM open_leaves
            WHERE batch_id = ?
            """,
            (batch_id,),
        ).fetchall()

        if not rows:
            raise ValueError(
                "cannot close an empty batch"
            )

        ordered = sorted(
            (
                (
                    row["did"],
                    bytes(row["leaf_hash"]),
                )
                for row in rows
            ),
            key=lambda item: item[1],
        )

        root_bytes, proof_map = build_tree(
            [
                leaf
                for _, leaf in ordered
            ]
        )

        root = root_bytes.hex()

        epoch_id = int(
            self.connection.execute(
                """
                SELECT COALESCE(MAX(epoch_id), 0) + 1 AS next
                FROM anchors
                """
            ).fetchone()["next"]
        )

        previous = self.connection.execute(
            """
            SELECT root
            FROM anchors
            ORDER BY epoch_id DESC
            LIMIT 1
            """
        ).fetchone()

        prev_hash = (
            previous["root"]
            if previous
            else None
        )

        for did, leaf in ordered:

            proof = [
                {
                    "sibling": step.sibling.hex(),
                    "position": step.position,
                }
                for step in proof_map[leaf]
            ]

            self.connection.execute(
                "INSERT INTO proofs VALUES (?, ?, ?, ?)",
                (
                    epoch_id,
                    did,
                    leaf.hex(),
                    json.dumps(
                        proof,
                        sort_keys=True,
                    ),
                ),
            )

        self.connection.execute(
            """
            UPDATE batches
            SET
                status = 'closed',
                epoch_id = ?,
                root = ?
            WHERE batch_id = ?
            """,
            (
                epoch_id,
                root,
                batch_id,
            ),
        )

        self.connection.execute(
            """
            INSERT INTO anchors
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                epoch_id,
                batch_id,
                root,
                prev_hash,
                time.time(),
            ),
        )

        self.connection.execute(
            """
            INSERT INTO batches
            VALUES (?, 'open', NULL, NULL, ?)
            """,
            (
                f"open-{epoch_id + 1}",
                time.time(),
            ),
        )

        self.connection.commit()

        proofs = {
            did: self.get_proof(
                did,
                epoch_id,
                log=False,
            )
            for did, _ in ordered
        }

        print(
            f"[BATCH_CLOSE] epoch={epoch_id} "
            f"root={root} "
            f"devices={len(ordered)}"
        )

        return BatchResult(
            batch_id,
            epoch_id,
            root,
            proofs,
        )

    def get_proof(
        self,
        did: str,
        epoch_id: int,
        *,
        log: bool = True,
    ) -> InclusionProof:

        row = self.connection.execute(
            """
            SELECT leaf_hash, proof
            FROM proofs
            WHERE did = ?
              AND epoch_id = ?
            """,
            (
                did,
                epoch_id,
            ),
        ).fetchone()

        if row is None:
            raise KeyError(
                f"proof not found for {did} at epoch {epoch_id}"
            )

        result = InclusionProof(
            did,
            epoch_id,
            row["leaf_hash"],
            json.loads(row["proof"]),
        )

        if log:
            print(
                f"[PROOF] did={did} "
                f"leaf={result.leaf_hash} "
                f"epoch={epoch_id} "
                f"result=ok"
            )

        return result

    def get_root(
        self,
        epoch_id: int,
    ) -> str:

        row = self.connection.execute(
            """
            SELECT root
            FROM anchors
            WHERE epoch_id = ?
            """,
            (epoch_id,),
        ).fetchone()

        if row is None:
            raise KeyError(
                f"root not found for epoch {epoch_id}"
            )

        print(
            f"[ROOT] epoch={epoch_id} "
            f"root={row['root']} "
            f"result=ok"
        )

        return row["root"]


_DEFAULT_NODE = FogNode()


def register_device(
    psk: str,
    did: str,
    public_key_bytes: bytes,
    metadata: dict,
) -> RegistrationResult:

    """Register through the module-level default fog node.

    The transport envelope must contain private ``_challenge`` and
    ``_signature`` fields. The normal workflow is ``Device.register``,
    which creates them during the protected connection; they are never
    persisted as device metadata.
    """

    transport = dict(metadata)

    challenge = transport.pop(
        "_challenge",
        None,
    )

    signature = transport.pop(
        "_signature",
        None,
    )

    return _DEFAULT_NODE.register_device(
        psk,
        did,
        public_key_bytes,
        transport,
        challenge=challenge,
        signature=signature,
    )


def close_batch(
    batch_id: str,
) -> BatchResult:

    return _DEFAULT_NODE.close_batch(
        batch_id
    )


def get_proof(
    did: str,
    epoch_id: int,
) -> InclusionProof:

    return _DEFAULT_NODE.get_proof(
        did,
        epoch_id,
    )


def get_root(
    epoch_id: int,
) -> str:

    return _DEFAULT_NODE.get_root(
        epoch_id
    )
