"""Phase 3 security attack integration tests."""

import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from phase1.device import Device
from phase1.fog_node import FogNode
from phase2.token_service import TokenService
from phase3.authorization import authorize


PSK = "test-psk"


def create_permanent_device(role="temperature_sensor"):
    """Create a device with permanent Phase 3 identity."""

    fog = FogNode(PSK)

    device = Device()

    registration = device.register(
        fog,
        PSK,
        metadata={"role": role},
    )

    batch = fog.close_batch(
        registration.batch_id
    )

    token_service = TokenService(
        fog.connection
    )

    return (
        fog,
        device,
        batch,
        token_service,
    )


def create_pending_device():
    """Create a device that is still pending for Phase 2."""

    fog = FogNode(PSK)

    device = Device()

    device.register(
        fog,
        PSK,
        metadata={"role": "temperature sensor"},
    )

    token_service = TokenService(
        fog.connection
    )

    return (
        fog,
        device,
        token_service,
    )


def sign_nonce(device, nonce):
    """Create a device proof-of-possession signature."""

    return device.private_key.sign(
        nonce.encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )


# ============================================================
# ATTACK 1
# REPLAY ATTACK / NONCE REUSE
# ============================================================


def test_replay_attack_is_rejected():

    (
        fog,
        device,
        token_service,
    ) = create_pending_device()

    token = token_service.issue_token(
        device.did
    )

    nonce = token_service.create_nonce()

    signature = sign_nonce(
        device,
        nonce,
    )

    first_request = token_service.request_resource(
        token,
        nonce,
        signature,
        "temperature_readings",
        "WRITE",
    )

    second_request = token_service.request_resource(
        token,
        nonce,
        signature,
        "temperature_readings",
        "WRITE",
    )

    assert first_request is True
    assert second_request is False


# ============================================================
# ATTACK 2
# TAMPERED PERMANENT IDENTITY
# ============================================================


def test_tampered_identity_is_rejected():

    (
        fog,
        device,
        batch,
        token_service,
    ) = create_permanent_device()

    tampered_key = bytearray(
        device.public_key_bytes
    )

    tampered_key[-1] = (
        tampered_key[-1] ^ 1
    )

    allowed, reason = authorize(
        fog,
        device.did,
        bytes(tampered_key),
        batch.epoch_id,
        "temperature_data",
        "read",
    )

    assert allowed is False
    assert (
        reason
        == "recomputed leaf does not match registered leaf"
    )


# ============================================================
# ATTACK 3
# STOLEN TOKEN / FAILED DEVICE PROOF
# ============================================================


def test_stolen_token_is_rejected():

    (
        fog,
        legitimate_device,
        token_service,
    ) = create_pending_device()

    token = token_service.issue_token(
        legitimate_device.did
    )

    attacker = Device()

    nonce = token_service.create_nonce()

    attacker_signature = sign_nonce(
        attacker,
        nonce,
    )

    result = token_service.request_resource(
        token,
        nonce,
        attacker_signature,
        "temperature_readings",
        "WRITE",
    )

    assert result is False


# ============================================================
# ATTACK 4
# EXPIRED TOKEN
# ============================================================


def test_expired_token_is_rejected():

    (
        fog,
        device,
        token_service,
    ) = create_pending_device()

    token = token_service.issue_token(
        device.did,
        lifetime_seconds=1,
    )

    time.sleep(2)

    valid, payload, reason = (
        token_service.verify_token(
            token
        )
    )

    assert valid is False
    assert (
        reason
        == "temporary token has expired"
    )


# ============================================================
# ATTACK 5
# REVOKED DEVICE
# ============================================================


def test_revoked_device_is_rejected_by_authorization():

    (
        fog,
        device,
        batch,
        token_service,
    ) = create_permanent_device()

    token_service.revoke_device(
        device.did,
        reason="security test",
    )

    allowed, reason = authorize(
        fog,
        device.did,
        device.public_key_bytes,
        batch.epoch_id,
        "temperature_data",
        "read",
    )

    assert allowed is False
    assert reason == "device revoked"
