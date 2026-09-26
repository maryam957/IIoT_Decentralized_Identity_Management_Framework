"""Phase 3 permanent identity authorization."""

import json

from phase2.token_service import TokenService
from phase3.verification import verify_identity


# Permanent access-control policy.
#
# role -> resource -> allowed operations
ACCESS_POLICY = {
    "temperature_sensor": {
        "temperature_data": ["read"],
    },
    "humidity_sensor": {
        "humidity_data": ["read"],
    },
    "gateway": {
        "temperature_data": ["read"],
        "humidity_data": ["read"],
    },
}


def get_device_role(fog, did):
    """Get the registered role of a device from Phase 1 metadata."""

    row = fog.connection.execute(
        "SELECT metadata FROM open_leaves WHERE did = ?",
        (did,),
    ).fetchone()

    if row is None:
        return None

    metadata = json.loads(row["metadata"])
    return metadata.get("role")


def authorize(
    fog,
    did,
    public_key_bytes,
    epoch_id,
    resource,
    operation,
):
    """
    Verify permanent identity and apply the access-control policy.

    Returns:
        (True, reason) when access is allowed.
        (False, reason) when access is denied.
    """

    # 1. Verify permanent identity.
    identity_valid, identity_reason = verify_identity(
        fog,
        did,
        public_key_bytes,
        epoch_id,
    )

    if not identity_valid:
        print(
            "[AUTHORIZATION] "
            "did={} result=DENY reason={}".format(
                did,
                identity_reason,
            )
        )
        return False, identity_reason

    # 2. Check current device revocation.
    token_service = TokenService(fog.connection)

    if token_service.is_device_revoked(did):
        print(
            "[AUTHORIZATION] "
            "did={} result=DENY reason=device revoked".format(did)
        )
        return False, "device revoked"

    # 3. Get the device's registered role.
    role = get_device_role(fog, did)

    if role is None:
        print(
            "[AUTHORIZATION] "
            "did={} result=DENY reason=role not found".format(did)
        )
        return False, "role not found"

    # 4. Check the permanent access-control policy.
    role_policy = ACCESS_POLICY.get(role, {})
    allowed_operations = role_policy.get(resource, [])

    if operation not in allowed_operations:
        print(
            "[AUTHORIZATION] "
            "did={} role={} resource={} operation={} result=DENY".format(
                did,
                role,
                resource,
                operation,
            )
        )
        return False, "operation not authorized"

    # 5. Access is allowed.
    print(
        "[AUTHORIZATION] "
        "did={} role={} resource={} operation={} result=ALLOW".format(
            did,
            role,
            resource,
            operation,
        )
    )

    return True, "access authorized"
