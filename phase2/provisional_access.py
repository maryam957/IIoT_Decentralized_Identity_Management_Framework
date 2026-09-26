"""Limited provisional access policy for Phase 2.

This policy applies only while a device is waiting for permanent
Merkle inclusion.

It is not the normal permanent access control mechanism from Phase 3.
"""


# =========================================================
# PHASE 2 PROVISIONAL PERMISSIONS
# =========================================================

PROVISIONAL_POLICIES = {
    "temperature sensor": {
        "temperature_readings": {
            "READ",
            "WRITE",
        },
    },

    "pressure sensor": {
        "pressure_readings": {
            "READ",
            "WRITE",
        },
    },

    "humidity sensor": {
        "humidity_readings": {
            "READ",
            "WRITE",
        },
    },

    "vibration sensor": {
        "vibration_readings": {
            "READ",
            "WRITE",
        },
    },
}


# =========================================================
# PROVISIONAL AUTHORIZATION
# =========================================================

def authorize(
    role: str,
    resource: str,
    operation: str,
) -> tuple[bool, str]:
    """
    Check whether a temporary Phase 2 credential may perform
    the requested operation.

    This function only controls provisional access.

    Permanent authorization after Merkle inclusion belongs
    to Phase 3.
    """

    # Normalize input so values such as "write" and "WRITE"
    # are handled consistently.
    role = role.strip().lower()
    resource = resource.strip().lower()
    operation = operation.strip().upper()

    # -----------------------------------------------------
    # Check device role
    # -----------------------------------------------------

    role_policy = PROVISIONAL_POLICIES.get(
        role
    )

    if role_policy is None:
        return (
            False,
            "role has no provisional permissions",
        )

    # -----------------------------------------------------
    # Check requested resource
    # -----------------------------------------------------

    resource_policy = role_policy.get(
        resource
    )

    if resource_policy is None:
        return (
            False,
            "resource not permitted for this role",
        )

    # -----------------------------------------------------
    # Check requested operation
    # -----------------------------------------------------

    if operation not in resource_policy:
        return (
            False,
            "operation not permitted for this resource",
        )

    return (
        True,
        "provisional access permitted",
    )