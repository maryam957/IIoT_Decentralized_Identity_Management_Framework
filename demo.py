"""Phase 1 demonstration, including deliberate proof corruption."""

from phase1 import Device, FogNode, verify_proof


def main() -> None:
    fog = FogNode(psk="demo-psk")
    devices = [Device("temperature sensor") for _ in range(5)]
    registrations = [device.register(fog, "demo-psk") for device in devices]
    batch = fog.close_batch(registrations[0].batch_id)
    device = devices[0]
    stored = batch.proofs[device.did]
    print(f"root={batch.root}")
    print(f"proof={stored}")
    print("proof valid:", verify_proof(bytes.fromhex(stored.leaf_hash), stored.proof, batch.root))
    corrupted = [dict(step) for step in stored.proof]
    if corrupted:
        corrupted[0]["sibling"] = ("00" if corrupted[0]["sibling"][:2] != "00" else "ff") + corrupted[0]["sibling"][2:]
    else:
        corrupted.append({"sibling": "00" * 32, "position": "right"})
    print("corrupted proof valid:", verify_proof(bytes.fromhex(stored.leaf_hash), corrupted, batch.root))


if __name__ == "__main__":
    main()