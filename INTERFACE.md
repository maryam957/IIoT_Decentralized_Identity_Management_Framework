# Phase 1 Interface

`phase1` is a standalone registration and batch-root layer. The normal device
workflow is `Device.register(fog, psk)`, followed by `fog.close_batch(batch_id)`.

## Leaf encoding

The leaf is `SHA-256(did_utf8 + public_key_der)`, with no delimiter. `did_utf8`
is the DID encoded as UTF-8. `public_key_der` is the device's P-256 public key
encoded as DER SubjectPublicKeyInfo. Leaf hashes and roots are lowercase
64-character hex strings.

## Proof structure

`InclusionProof` has fields `did: str`, `epoch_id: int`, `leaf_hash: str`, and
`proof: list[dict[str, str]]`. Each proof item has exactly `sibling` (a
64-character hex hash) and `position` (`"left"` or `"right"`). `position`
identifies the sibling's side in the parent hash. Verification is provided by
`phase1.merkle.verify_proof(bytes.fromhex(leaf_hash), proof, root)`.

Merkle parents are `SHA-256(left + right)`. Leaves are sorted lexicographically
by their raw hash bytes before tree construction. An odd level duplicates its
last node. These rules make roots deterministic.

## Epochs and persistence

The first closed batch is epoch `1`; each later close increments the integer.
Roots are stored in SQLite table `anchors`, with the batch ID, timestamp, and
previous root. Open leaves and generated proofs are also stored in SQLite.

`FogNode` accepts `db_path`, defaulting to `":memory:"`. The CLI uses `phase1.db`
so `register` and `close-batch` can be separate processes.

The protected connection currently uses a PSK comparison. A real deployment
would add TLS or another authenticated transport around this connection.