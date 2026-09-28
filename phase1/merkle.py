"""Small, intentionally transparent Merkle tree implementation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def sha256(value: bytes) -> bytes:
    """Return the SHA256 digest of a byte value."""
    return hashlib.sha256(value).digest()


@dataclass(frozen=True)
class ProofStep:
    sibling: bytes
    position: str


def build_tree(
    leaves: list[bytes],
) -> tuple[bytes, dict[bytes, list[ProofStep]]]:
    """
    Build a Merkle tree and generate an inclusion proof
    for every leaf.

    Duplicate-last padding is used whenever a tree level
    contains an odd number of nodes.

    Important:
    When the final node is duplicated for hashing, only
    the node hash is duplicated. The original leaf
    membership list is not duplicated.
    """

    if not leaves:
        raise ValueError(
            "cannot build a Merkle tree with no leaves"
        )

    if len(set(leaves)) != len(leaves):
        raise ValueError(
            "duplicate leaf hashes are not supported"
        )

    # Each node stores:
    #
    # 1. The hash of that node
    # 2. The original leaves represented by that node
    #
    # The second value is used to construct a proof
    # for every original device leaf.

    current = [
        (leaf, [leaf])
        for leaf in leaves
    ]

    proofs: dict[bytes, list[ProofStep]] = {
        leaf: []
        for leaf in leaves
    }

    while len(current) > 1:

        next_level: list[
            tuple[bytes, list[bytes]]
        ] = []

        for index in range(
            0,
            len(current),
            2,
        ):

            left_hash, left_leaves = current[index]

            # =================================================
            # NORMAL PAIR
            # =================================================

            if index + 1 < len(current):

                right_hash, right_leaves = (
                    current[index + 1]
                )

                parent_hash = sha256(
                    left_hash + right_hash
                )

                # Leaves represented by the left node
                # require the right node in their proof.

                for leaf in left_leaves:
                    proofs[leaf].append(
                        ProofStep(
                            sibling=right_hash,
                            position="right",
                        )
                    )

                # Leaves represented by the right node
                # require the left node in their proof.

                for leaf in right_leaves:
                    proofs[leaf].append(
                        ProofStep(
                            sibling=left_hash,
                            position="left",
                        )
                    )

                parent_leaves = (
                    left_leaves + right_leaves
                )

            # =================================================
            # ODD NODE
            # =================================================

            else:

                # There is no right partner.
                #
                # Duplicate the HASH of the final node
                # according to duplicate-last padding.

                right_hash = left_hash

                parent_hash = sha256(
                    left_hash + right_hash
                )

                # The duplicated hash acts as the right
                # sibling for every original leaf represented
                # by this node.

                for leaf in left_leaves:
                    proofs[leaf].append(
                        ProofStep(
                            sibling=right_hash,
                            position="right",
                        )
                    )

                # IMPORTANT FIX:
                #
                # Do not use:
                #
                # left_leaves + left_leaves
                #
                # The hash is duplicated for Merkle tree
                # construction, but the original device
                # membership must not be duplicated.

                parent_leaves = list(left_leaves)

            next_level.append(
                (
                    parent_hash,
                    parent_leaves,
                )
            )

        current = next_level

    root = current[0][0]

    return root, proofs


def verify_proof(
    leaf: bytes,
    proof: list[dict[str, str]],
    root: str | bytes,
) -> bool:
    """
    Verify a device inclusion proof against a trusted
    Merkle root.
    """

    computed = leaf

    try:

        for step in proof:

            sibling = bytes.fromhex(
                step["sibling"]
            )

            position = step["position"]

            if position == "left":

                computed = sha256(
                    sibling + computed
                )

            elif position == "right":

                computed = sha256(
                    computed + sibling
                )

            else:
                return False

        expected = (
            bytes.fromhex(root)
            if isinstance(root, str)
            else root
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return False

    return computed == expected