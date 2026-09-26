from phase1.device import Device
from phase1.fog_node import FogNode
from phase2.token_service import TokenService
from phase3.authorization import authorize


PSK = "test-psk"


def create_device_with_role(role):
    fog = FogNode(PSK)
    device = Device()

    registration = device.register(
        fog,
        PSK,
        metadata={"role": role},
    )

    batch = fog.close_batch(registration.batch_id)

    return fog, device, batch


def test_authorized_operation_is_allowed():
    fog, device, batch = create_device_with_role(
        "temperature_sensor"
    )

    allowed, reason = authorize(
        fog,
        device.did,
        device.public_key_bytes,
        batch.epoch_id,
        "temperature_data",
        "read",
    )

    assert allowed is True
    assert reason == "access authorized"


def test_unauthorized_operation_is_denied():
    fog, device, batch = create_device_with_role(
        "temperature_sensor"
    )

    allowed, reason = authorize(
        fog,
        device.did,
        device.public_key_bytes,
        batch.epoch_id,
        "temperature_data",
        "write",
    )

    assert allowed is False
    assert reason == "operation not authorized"


def test_wrong_resource_is_denied():
    fog, device, batch = create_device_with_role(
        "temperature_sensor"
    )

    allowed, reason = authorize(
        fog,
        device.did,
        device.public_key_bytes,
        batch.epoch_id,
        "humidity_data",
        "read",
    )

    assert allowed is False
    assert reason == "operation not authorized"


def test_revoked_device_is_denied():
    fog, device, batch = create_device_with_role(
        "temperature_sensor"
    )

    token_service = TokenService(fog.connection)
    token_service.revoke_device(device.did)

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


def test_invalid_identity_is_denied():
    fog, device, batch = create_device_with_role(
        "temperature_sensor"
    )

    tampered_key = bytearray(device.public_key_bytes)
    tampered_key[-1] = tampered_key[-1] ^ 1

    allowed, reason = authorize(
        fog,
        device.did,
        bytes(tampered_key),
        batch.epoch_id,
        "temperature_data",
        "read",
    )

    assert allowed is False
    assert reason == "recomputed leaf does not match registered leaf"


def test_unknown_role_is_denied():
    fog, device, batch = create_device_with_role(
        "unknown_device"
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
    assert reason == "operation not authorized"
