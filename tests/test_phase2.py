"""Automated tests for Phase 2 temporary token based bridging."""

import time

import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from phase1.device import Device
from phase1.fog_node import FogNode
from phase2.token_service import TokenError, TokenService


# ============================================================
# HELPERS
# ============================================================


def create_registered_device(
    device_type="temperature sensor",
):
    """
    Create one fog node, register one device through Phase 1,
    and create a Phase 2 TokenService using the same database.
    """

    fog = FogNode()

    device = Device(device_type)

    registration = device.register(
        fog,
        fog.psk,
    )

    token_service = TokenService(
        fog.connection
    )

    return (
        fog,
        device,
        registration,
        token_service,
    )


def sign_nonce(device, nonce):
    """
    Sign a Phase 2 nonce using the legitimate device's
    Phase 1 ECC private key.
    """

    return device.private_key.sign(
        nonce.encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )


# ============================================================
# TEST 1
# REGISTERED DEVICE CAN RECEIVE TOKEN
# ============================================================


def test_registered_device_can_receive_token():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        device.did
    )

    assert token is not None
    assert isinstance(token, str)

    valid, payload, reason = (
        token_service.verify_token(token)
    )

    assert valid is True
    assert payload is not None
    assert reason == "temporary token valid"


# ============================================================
# TEST 2
# TOKEN CONTAINS REQUIRED INFORMATION
# ============================================================


def test_token_contains_required_claims():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        device.did
    )

    valid, payload, reason = (
        token_service.verify_token(token)
    )

    assert valid is True

    assert "token_id" in payload
    assert "did" in payload
    assert "public_key" in payload
    assert "metadata" in payload
    assert "role" in payload
    assert "batch_id" in payload
    assert "issued_at" in payload
    assert "expiry" in payload
    assert "state" in payload

    assert payload["did"] == device.did

    assert (
        payload["role"]
        == "temperature sensor"
    )

    assert payload["state"] == "provisional"

    assert (
        payload["expiry"]
        > payload["issued_at"]
    )


# ============================================================
# TEST 3
# VALID PROVISIONAL ACCESS
# ============================================================


def test_valid_provisional_access():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        device.did
    )

    nonce = token_service.create_nonce()

    signature = sign_nonce(
        device,
        nonce,
    )

    result = token_service.request_resource(
        token,
        nonce,
        signature,
        "temperature_readings",
        "WRITE",
    )

    assert result is True


# ============================================================
# TEST 4
# REPLAY ATTACK IS BLOCKED
# ============================================================


def test_replay_attack_is_blocked():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        device.did
    )

    nonce = token_service.create_nonce()

    signature = sign_nonce(
        device,
        nonce,
    )

    first_request = (
        token_service.request_resource(
            token,
            nonce,
            signature,
            "temperature_readings",
            "WRITE",
        )
    )

    second_request = (
        token_service.request_resource(
            token,
            nonce,
            signature,
            "temperature_readings",
            "WRITE",
        )
    )

    assert first_request is True
    assert second_request is False


# ============================================================
# TEST 5
# STOLEN TOKEN IS BLOCKED
# ============================================================


def test_stolen_token_is_blocked():

    (
        fog,
        legitimate_device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        legitimate_device.did
    )

    attacker = Device(
        "temperature sensor"
    )

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
# TEST 6
# EXPIRED TOKEN IS BLOCKED
# ============================================================


def test_expired_token_is_blocked():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        device.did,
        lifetime_seconds=1,
    )

    time.sleep(2)

    valid, payload, reason = (
        token_service.verify_token(token)
    )

    assert valid is False
    assert reason == "temporary token has expired"


# ============================================================
# TEST 7
# REVOKED TOKEN IS BLOCKED
# ============================================================


def test_revoked_token_is_blocked():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        device.did
    )

    revoked = token_service.revoke_token(
        token
    )

    assert revoked is True

    valid, payload, reason = (
        token_service.verify_token(token)
    )

    assert valid is False
    assert (
        reason
        == "temporary token has been revoked"
    )


# ============================================================
# TEST 8
# DEVICE REVOCATION INVALIDATES TOKEN
# ============================================================


def test_revoked_device_token_is_blocked():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        device.did
    )

    revoked = token_service.revoke_device(
        device.did,
        reason="automated security test",
    )

    assert revoked is True

    valid, payload, reason = (
        token_service.verify_token(token)
    )

    assert valid is False

    assert (
        reason
        == "device has been revoked since token issuance"
    )


# ============================================================
# TEST 9
# REVOKED DEVICE CANNOT RECEIVE NEW TOKEN
# ============================================================


def test_revoked_device_cannot_receive_new_token():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token_service.revoke_device(
        device.did,
        reason="automated security test",
    )

    with pytest.raises(
        TokenError
    ):

        token_service.issue_token(
            device.did
        )


# ============================================================
# TEST 10
# UNREGISTERED DEVICE CANNOT RECEIVE TOKEN
# ============================================================


def test_unregistered_device_cannot_receive_token():

    fog = FogNode()

    token_service = TokenService(
        fog.connection
    )

    unregistered_device = Device(
        "temperature sensor"
    )

    with pytest.raises(
        TokenError
    ):

        token_service.issue_token(
            unregistered_device.did
        )


# ============================================================
# TEST 11
# UNAUTHORIZED PROVISIONAL ACCESS IS BLOCKED
# ============================================================


def test_unauthorized_provisional_access_is_blocked():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        device.did
    )

    nonce = token_service.create_nonce()

    signature = sign_nonce(
        device,
        nonce,
    )

    result = token_service.request_resource(
        token,
        nonce,
        signature,
        "production_line",
        "STOP",
    )

    assert result is False


# ============================================================
# TEST 12
# TAMPERED TOKEN IS BLOCKED
# ============================================================


def test_tampered_token_is_blocked():

    (
        fog,
        device,
        registration,
        token_service,
    ) = create_registered_device()

    token = token_service.issue_token(
        device.did
    )

    encoded_payload, encoded_signature = (
        token.split(".", 1)
    )

    # Change one character in the signed payload.
    replacement = (
        "A"
        if encoded_payload[0] != "A"
        else "B"
    )

    tampered_payload = (
        replacement
        + encoded_payload[1:]
    )

    tampered_token = (
        tampered_payload
        + "."
        + encoded_signature
    )

    valid, payload, reason = (
        token_service.verify_token(
            tampered_token
        )
    )

    assert valid is False

    assert (
        reason
        == "temporary token signature is invalid"
    )