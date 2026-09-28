"""Phase 3 and security demonstration.

Phase 1 and Phase 2 lifecycle is demonstrated by run_simulation.py.

This demo focuses on:
    permanent identity verification
    resource authorization
    tampered identity detection
    tampered Merkle proof detection
    revocation and current authorization
"""


from phase1 import Device, FogNode, verify_proof
from phase3.verification import verify_identity
from phase3.authorization import authorize
from phase2.token_service import TokenService


def section(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def main() -> None:

    # =========================================================
    # SYSTEM SETUP
    # =========================================================

    section("IIoT DECENTRALIZED IDENTITY MANAGEMENT DEMO")

    print("Creating fog node and simulated devices...")

    fog = FogNode(
        psk="demo-psk"
    )

    devices = [
        Device("temperature sensor")
        for _ in range(5)
    ]

    registrations = []

    # =========================================================
    # PHASE 1 — REGISTRATION
    # =========================================================

    section("PHASE 1 — DEVICE REGISTRATION")

    for index, device in enumerate(
        devices,
        start=1,
    ):

        registration = device.register(
            fog,
            "demo-psk",
        )

        registrations.append(
            registration
        )

        print(
            "Device,",
            index,
            "DID,",
            registration.did,
            "Role,",
            device.device_type,
            "Status,",
            "QUEUED",
        )

    # =========================================================
    # PHASE 1 — BATCH FINALIZATION
    # =========================================================

    section("PHASE 1 — BATCH FINALIZATION")

    batch = fog.close_batch(
        registrations[0].batch_id
    )

    print(
        "Devices in batch,",
        len(registrations),
    )

    print(
        "Epoch ID,",
        batch.epoch_id,
    )

    print(
        "Merkle root,",
        batch.root,
    )

    print(
        "Inclusion proofs generated,",
        len(batch.proofs),
    )

    # =========================================================
    # VALID MERKLE PROOF
    # =========================================================

    section("MERKLE INCLUSION PROOF")

    device = devices[0]

    stored = batch.proofs[
        device.did
    ]

    print(
        "Device DID,",
        stored.did,
    )

    print(
        "Leaf hash,",
        stored.leaf_hash,
    )

    print(
        "Proof steps,",
        len(stored.proof),
    )

    valid = verify_proof(
        bytes.fromhex(
            stored.leaf_hash
        ),
        stored.proof,
        batch.root,
    )

    print(
        "Merkle proof verification,",
        valid,
    )

    # =========================================================
    # PHASE 3 — IDENTITY VERIFICATION
    # =========================================================

    section(
        "PHASE 3 — PERMANENT IDENTITY VERIFICATION"
    )

    identity_valid, identity_reason = (
        verify_identity(
            fog,
            device.did,
            device.public_key_bytes,
            batch.epoch_id,
        )
    )

    print(
        "Device DID,",
        device.did,
    )

    print(
        "Epoch ID,",
        batch.epoch_id,
    )

    print(
        "Leaf recomputation,",
        "CHECKED",
    )

    print(
        "Registered leaf,",
        stored.leaf_hash,
    )

    print(
        "Trusted Merkle root,",
        batch.root,
    )

    print(
        "Identity verification,",
        identity_valid,
    )

    print(
        "Result,",
        identity_reason,
    )

    # =========================================================
    # PHASE 3 — AUTHORIZATION
    # =========================================================

    section(
        "PHASE 3 — RESOURCE AUTHORIZATION"
    )

    allowed, reason = authorize(
        fog,
        device.did,
        device.public_key_bytes,
        batch.epoch_id,
        "temperature_data",
        "read",
    )

    print(
        "Device DID,",
        device.did,
    )

    print(
        "Resource,",
        "temperature_data",
    )

    print(
        "Operation,",
        "read",
    )

    print(
        "Authorization,",
        allowed,
    )

    print(
        "Reason,",
        reason,
    )

    print(
        "ACCESS,",
        "ALLOW" if allowed else "DENY",
    )

    # =========================================================
    # SECURITY ATTACK 1
    # TAMPERED MERKLE PROOF
    # =========================================================

    section(
        "SECURITY TEST 1 — TAMPERED MERKLE PROOF"
    )

    corrupted = [
        dict(step)
        for step in stored.proof
    ]

    if corrupted:

        original = corrupted[0][
            "sibling"
        ]

        corrupted[0][
            "sibling"
        ] = (
            "00"
            if original[:2] != "00"
            else "ff"
        ) + original[2:]

    else:

        corrupted.append(
            {
                "sibling": "00" * 32,
                "position": "right",
            }
        )

    tampered_valid = verify_proof(
        bytes.fromhex(
            stored.leaf_hash
        ),
        corrupted,
        batch.root,
    )

    print(
        "Original proof,",
        "VALID",
    )

    print(
        "Modified sibling hash,",
        "TAMPERED",
    )

    print(
        "Tampered proof verification,",
        tampered_valid,
    )

    print(
        "Attack result,",
        "DENY" if not tampered_valid else "ALLOW",
    )

    # =========================================================
    # SECURITY ATTACK 2
    # TAMPERED PUBLIC KEY
    # =========================================================

    section(
        "SECURITY TEST 2 — TAMPERED IDENTITY"
    )

    tampered_key = bytearray(
        device.public_key_bytes
    )

    tampered_key[-1] ^= 1

    tampered_identity, tampered_reason = (
        verify_identity(
            fog,
            device.did,
            bytes(tampered_key),
            batch.epoch_id,
        )
    )

    print(
        "Original public key,",
        "VALID",
    )

    print(
        "Modified public key,",
        "TAMPERED",
    )

    print(
        "Identity verification,",
        tampered_identity,
    )

    print(
        "Reason,",
        tampered_reason,
    )

    print(
        "Attack result,",
        "DENY" if not tampered_identity else "ALLOW",
    )

    # =========================================================
    # SECURITY ATTACK 3
    # UNAUTHORIZED OPERATION
    # =========================================================

    section(
        "SECURITY TEST 3 — UNAUTHORIZED OPERATION"
    )

    denied, denied_reason = authorize(
        fog,
        device.did,
        device.public_key_bytes,
        batch.epoch_id,
        "humidity_data",
        "write",
    )

    print(
        "Device role,",
        "temperature sensor",
    )

    print(
        "Requested resource,",
        "humidity_data",
    )

    print(
        "Requested operation,",
        "write",
    )

    print(
        "Authorization,",
        denied,
    )

    print(
        "Reason,",
        denied_reason,
    )

    print(
        "Attack result,",
        "DENY" if not denied else "ALLOW",
    )

    # =========================================================
    # REVOCATION
    # =========================================================

    section(
        "REVOCATION — CURRENT AUTHORIZATION"
    )

    token_service = TokenService(
        fog.connection
    )

    revoked = token_service.revoke_device(
        device.did,
        reason="demo revocation",
    )

    print(
        "Device DID,",
        device.did,
    )

    print(
        "Device revoked,",
        revoked,
    )

    print(
        "Historical Merkle proof,",
        "VALID",
    )

    print(
        "Current device status,",
        "REVOKED",
    )

    print()
    print(
        "Historical membership != Current authorization"
    )

    revoked_allowed, revoked_reason = authorize(
        fog,
        device.did,
        device.public_key_bytes,
        batch.epoch_id,
        "temperature_data",
        "read",
    )

    print(
        "Authorization after revocation,",
        revoked_allowed,
    )

    print(
        "Reason,",
        revoked_reason,
    )

    print(
        "ACCESS,",
        "DENY" if not revoked_allowed else "ALLOW",
    )

    # =========================================================
    # FINAL SUMMARY
    # =========================================================

    section("DEMO SUMMARY")

    print(
        "Phase 1 registration,",
        "DEMONSTRATED",
    )

    print(
        "Merkle root and inclusion proof,",
        "DEMONSTRATED",
    )

    print(
        "Permanent identity verification,",
        "DEMONSTRATED",
    )

    print(
        "Resource authorization,",
        "DEMONSTRATED",
    )

    print(
        "Tampered proof detection,",
        "DEMONSTRATED",
    )

    print(
        "Tampered identity detection,",
        "DEMONSTRATED",
    )

    print(
        "Unauthorized operation detection,",
        "DEMONSTRATED",
    )

    print(
        "Revocation and authorization denial,",
        "DEMONSTRATED",
    )

    print()
    print(
        "Phase 2 temporary-token lifecycle is demonstrated",
        "by run_simulation.py",
    )


if __name__ == "__main__":
    main()
