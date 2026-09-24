"""Phase 1 demonstration, including deliberate proof corruption."""

from phase1 import Device, FogNode, verify_proof


def main() -> None:
    print("\n=== Phase 1 IIoT Demo ===")
    print("Creating fog node and 5 simulated devices...\n")

    fog = FogNode(psk="demo-psk")
    devices = [Device("temperature sensor") for _ in range(5)]
    registrations = [device.register(fog, "demo-psk") for device in devices]

    print("\n--- Registration results ---")
    for reg in registrations:
        print(f"Device DID: {reg.did}")
        print(f"  Leaf hash: {reg.leaf_hash}")
        print(f"  Batch: {reg.batch_id}")

    batch = fog.close_batch(registrations[0].batch_id)
    device = devices[0]
    stored = batch.proofs[device.did]

    print("\n--- Batch closed ---")
    print(f"Epoch ID: {batch.epoch_id}")
    print(f"Merkle root: {batch.root}")
    print(f"Number of devices: {len(registrations)}")

    print("\n--- Inclusion proof for the first device ---")
    print(f"DID: {stored.did}")
    print(f"Leaf hash: {stored.leaf_hash}")
    for idx, step in enumerate(stored.proof, start=1):
        print(f"  Step {idx}: position={step['position']}, sibling={step['sibling']}")

    valid = verify_proof(bytes.fromhex(stored.leaf_hash), stored.proof, batch.root)
    print(f"\nProof verification result: {valid}")

    corrupted = [dict(step) for step in stored.proof]
    if corrupted:
        corrupted[0]["sibling"] = ("00" if corrupted[0]["sibling"][:2] != "00" else "ff") + corrupted[0]["sibling"][2:]
    else:
        corrupted.append({"sibling": "00" * 32, "position": "right"})

    print("\n--- Tampering demonstration ---")
    print("Changing one sibling hash in the proof...")
    print(f"Modified proof step: {corrupted[0]}")
    tampered_valid = verify_proof(bytes.fromhex(stored.leaf_hash), corrupted, batch.root)
    print(f"Tampered proof verification result: {tampered_valid}")
    print("\nThis shows that even a single-byte change in the proof breaks verification.")


if __name__ == "__main__":
    main()