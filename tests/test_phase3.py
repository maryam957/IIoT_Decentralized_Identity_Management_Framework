from phase1.device import Device
from phase1.fog_node import FogNode
from phase1.merkle import verify_proof
from phase3.verification import verify_identity


PSK = "test-psk"


def create_permanent_device():
    fog = FogNode(PSK)
    device = Device()

    registration = device.register(
        fog,
        PSK,
    )

    batch = fog.close_batch(
        registration.batch_id
    )

    return fog, device, batch


def test_valid_permanent_identity():
    fog, device, batch = create_permanent_device()

    valid, reason = verify_identity(
        fog,
        device.did,
        device.public_key_bytes,
        batch.epoch_id,
    )

    assert valid is True
    assert reason == "permanent identity verified"


def test_tampered_public_key_is_rejected():
    fog, device, batch = create_permanent_device()

    tampered_key = bytearray(
        device.public_key_bytes
    )

    tampered_key[-1] = (
        tampered_key[-1] ^ 1
    )

    valid, reason = verify_identity(
        fog,
        device.did,
        bytes(tampered_key),
        batch.epoch_id,
    )

    assert valid is False
    assert reason == (
        "recomputed leaf does not match registered leaf"
    )


def test_tampered_merkle_proof_is_rejected():
    fog = FogNode(PSK)

    device = Device()
    other_device = Device()

    registration = device.register(
        fog,
        PSK,
    )

    other_device.register(
        fog,
        PSK,
    )

    batch = fog.close_batch(
        registration.batch_id
    )

    proof = fog.get_proof(
        device.did,
        batch.epoch_id,
        log=False,
    )

    assert len(proof.proof) > 0

    original_sibling = proof.proof[0]["sibling"]

    if original_sibling != "00" * 32:
        proof.proof[0]["sibling"] = "00" * 32
    else:
        proof.proof[0]["sibling"] = "ff" * 32

    root = fog.get_root(
        batch.epoch_id
    )

    valid = verify_proof(
        bytes.fromhex(proof.leaf_hash),
        proof.proof,
        root,
    )

    assert valid is False


def test_missing_epoch_is_rejected():
    fog, device, batch = create_permanent_device()

    valid, reason = verify_identity(
        fog,
        device.did,
        device.public_key_bytes,
        batch.epoch_id + 999,
    )

    assert valid is False
    assert reason == (
        "permanent inclusion proof not found"
    )
