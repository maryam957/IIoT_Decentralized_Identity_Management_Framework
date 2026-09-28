"""Phase 3 identity verification.

This module checks that a registered IIoT device
is included in a trusted Merkle epoch.

Identity verification checks Merkle membership.
Authorization and revocation are checked separately.
"""

from __future__ import annotations

import hashlib

from phase1.fog_node import FogNode
from phase1.merkle import verify_proof


class VerificationError(ValueError):
    """Error used during identity verification."""


def compute_leaf(did: str, public_key_bytes: bytes) -> str:
    """Create the device leaf hash."""

    return hashlib.sha256(
        did.encode("utf-8") + public_key_bytes
    ).hexdigest()


def verify_identity(
    fog: FogNode,
    did: str,
    public_key_bytes: bytes,
    epoch_id: int,
) -> tuple[bool, str]:
    """
    Check if the device belongs to the given Merkle epoch.

    Steps:
    1. Create the device leaf.
    2. Get the device proof.
    3. Get the Merkle root.
    4. Check the Merkle proof.
    """

    # Create the device leaf
    leaf_hash = compute_leaf(
        did,
        public_key_bytes,
    )

    # Get the device proof
    try:
        proof = fog.get_proof(
            did,
            epoch_id,
            log=False,
        )
    except KeyError:
        return (
            False,
            "permanent inclusion proof not found",
        )

    # Check if the leaf matches
    if proof.leaf_hash != leaf_hash:
        return (
            False,
            "recomputed leaf does not match registered leaf",
        )

    # Get the Merkle root
    try:
        root = fog.get_root(
            epoch_id,
        )
    except KeyError:
        return (
            False,
            "trusted epoch root not found",
        )

    # Check the Merkle proof
    valid = verify_proof(
        bytes.fromhex(leaf_hash),
        proof.proof,
        root,
    )

    if not valid:
        return (
            False,
            "Merkle inclusion proof verification failed",
        )

    print(
	    "[IDENTITY_VERIFY]",
	    "did=", did,
	    "epoch=", epoch_id,
	    "leaf=", leaf_hash,
	    "result=ok"
	)

    return (
        True,
        "permanent identity verified",
    )
