import pytest

from phase1.device import Device
from phase1.fog_node import FogNode, RegistrationError
from phase1.merkle import verify_proof


PSK = "test-psk"


def test_successful_registration_and_proof():
    fog = FogNode(PSK)
    device = Device()
    registration = device.register(fog, PSK)
    batch = fog.close_batch(registration.batch_id)
    proof = fog.get_proof(device.did, batch.epoch_id)
    assert proof.leaf_hash == registration.leaf_hash
    assert verify_proof(bytes.fromhex(proof.leaf_hash), proof.proof, fog.get_root(batch.epoch_id))


def test_pop_failure_rejects_registration():
    fog = FogNode(PSK)
    device = Device()
    fog.authenticate(PSK)
    challenge = fog.create_challenge(device.did)
    with pytest.raises(RegistrationError, match="proof-of-possession"):
        fog.register_device(PSK, device.did, device.public_key_bytes, {}, challenge=challenge, signature=b"bad")


def test_same_devices_produce_stable_root():
    devices = [Device(did=f"did:iiot:fixed-{index}") for index in range(5)]
    first = FogNode(PSK)
    first_regs = [device.register(first, PSK) for device in devices]
    first_root = first.close_batch(first_regs[0].batch_id).root

    second = FogNode(PSK)
    second_regs = [device.register(second, PSK) for device in devices]
    second_root = second.close_batch(second_regs[0].batch_id).root
    assert first_root == second_root


def test_corrupted_proof_fails_verification():
    fog = FogNode(PSK)
    device = Device()
    registration = device.register(fog, PSK)
    batch = fog.close_batch(registration.batch_id)
    proof = batch.proofs[device.did]
    corrupted = proof.proof + [{"sibling": "00" * 32, "position": "right"}]
    assert not verify_proof(bytes.fromhex(proof.leaf_hash), corrupted, batch.root)