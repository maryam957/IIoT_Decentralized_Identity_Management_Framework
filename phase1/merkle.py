"""Small, intentionally transparent Merkle tree implementation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


@dataclass(frozen=True)
class ProofStep:
    sibling: bytes
    position: str


def build_tree(leaves: list[bytes]) -> tuple[bytes, dict[bytes, list[ProofStep]]]:
    """Return the root and proofs, using duplicate-last padding for odd levels."""
    if not leaves:
        raise ValueError("cannot build a Merkle tree with no leaves")
    if len(set(leaves)) != len(leaves):
        raise ValueError("duplicate leaf hashes are not supported")

    current = [(leaf, [leaf]) for leaf in leaves]
    proofs: dict[bytes, list[ProofStep]] = {leaf: [] for leaf in leaves}
    while len(current) > 1:
        next_level: list[tuple[bytes, list[bytes]]] = []
        for index in range(0, len(current), 2):
            left, left_leaves = current[index]
            right, right_leaves = current[index + 1] if index + 1 < len(current) else (left, left_leaves)
            next_level.append((sha256(left + right), left_leaves + right_leaves))
            for leaf in left_leaves:
                proofs[leaf].append(ProofStep(right, "right"))
            if index + 1 < len(current):
                for leaf in right_leaves:
                    proofs[leaf].append(ProofStep(left, "left"))
        current = next_level
    return current[0][0], proofs


def verify_proof(leaf: bytes, proof: list[dict[str, str]], root: str | bytes) -> bool:
    """Verify a leaf against a hex root and the public proof representation."""
    computed = leaf
    try:
        for step in proof:
            sibling = bytes.fromhex(step["sibling"])
            if step["position"] == "left":
                computed = sha256(sibling + computed)
            elif step["position"] == "right":
                computed = sha256(computed + sibling)
            else:
                return False
        expected = bytes.fromhex(root) if isinstance(root, str) else root
    except (KeyError, TypeError, ValueError):
        return False
    return computed == expected