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

# Phase 2 Interface

`phase2` implements temporary token based bridging for devices that have
successfully completed Phase 1 registration but do not yet have a permanent
Merkle inclusion proof.

Phase 2 does not create a new device identity or register the device again.
The same DID, ECC key pair, metadata, fog node, and Phase 1 registration
record are reused throughout the device lifecycle.

## Temporary token issuance

A device may require resource access while its registration batch is still
open. At this point, the device is authenticated and queued by Phase 1, but
the Merkle tree has not yet been finalized.

`TokenService` issues a short lived credential signed by the fog node.

The temporary token contains information including:

* device DID
* device public key
* device role or type
* selected metadata
* assigned batch
* issue time
* expiry time

A temporary token represents provisional identity only. It does not replace
the permanent Merkle inclusion proof.

The device lifecycle during this process is:

`CREATED -> QUEUED -> PROVISIONAL -> PERMANENT`

## Temporary token validation

Before provisional access is accepted, the fog node validates the temporary
credential.

Validation includes:

* fog signature verification
* token expiry
* token revocation status
* device revocation status
* fresh request nonce
* nonce reuse detection
* device proof of possession
* provisional access policy

A request is rejected if any required validation fails.

## Replay protection

Every provisional resource request requires a fresh nonce.

Previously used nonces are recorded by the fog node. Reusing a nonce causes
the request to be denied even when the temporary token itself is otherwise
valid.

This prevents an intercepted valid request from being replayed.

## Proof of possession

Possession of a temporary token alone is not sufficient for access.

The requesting device signs the request challenge or nonce using its ECC
private key. The fog node verifies the signature using the public key
associated with the registered DID.

Therefore, stealing a valid temporary token without possessing the
corresponding private key does not provide access.

## Provisional access

`phase2.provisional_access` defines the limited permissions available while a
device is waiting for permanent registration.

The provisional policy is role based. For example, a temperature sensor may
read or write temperature readings while waiting for its permanent proof.

This access is intentionally temporary and limited. Permanent identity
verification and normal resource authorization belong to Phase 3.

## Token expiry and revocation

Temporary tokens have a limited lifetime.

An expired token is rejected automatically.

Tokens can also be revoked before their expiry. Once a token is present in
the revocation state, subsequent requests using that token are denied.

Device level revocation is also supported. A revoked device cannot obtain a
new temporary credential.

Revocation information is stored using the same SQLite connection used by
the fog node so that Phase 1 and Phase 2 operate on shared system state.


# Integrated Simulation Layer

The `simulation` package connects the individual phase implementations into
one continuous device lifecycle.

The simulation layer does not reimplement the cryptographic functionality of
Phase 1 or Phase 2. Instead, it controls when their existing functions are
called.

This avoids separate demonstrations creating unrelated devices for each
phase.

## Simulation clock

`SimulationClock` provides deterministic virtual time.

The simulation uses virtual time instead of waiting with real time delays.
This allows a complete registration epoch to be demonstrated immediately
while preserving the ordering of device arrivals, registration cutoff, and
epoch finalization.

For the current demonstration:

* epoch starts at `t=0`
* registration cutoff occurs at `t=25`
* epoch finalization occurs at `t=30`

These values are simulation parameters and can be changed through the epoch
configuration.

## Epoch management

`EpochManager` controls the registration window and epoch lifecycle.

Before the registration cutoff, newly arriving devices may join the current
registration batch.

After the cutoff, new arrivals are not added to the closing batch and must
wait for the next epoch.

At the finalization deadline, the manager calls the existing Phase 1 batch
finalization functionality.

Phase 1 then:

* deterministically sorts the eligible leaves
* constructs the Merkle tree
* calculates the epoch root
* anchors the root
* generates device specific inclusion proofs

The epoch manager therefore controls when finalization occurs, while Phase 1
remains responsible for how the Merkle tree and proofs are constructed.

## Device lifecycle

`DeviceAgent` keeps one simulated device instance throughout the workflow.

The underlying Phase 1 `Device` is created once. Its DID and ECC key pair are
not regenerated when the simulation moves into Phase 2.

A normal device follows:

`CREATED -> QUEUED -> PERMANENT`

A device requiring access before finalization follows:

`CREATED -> QUEUED -> PROVISIONAL -> PERMANENT`

This ensures that the device receiving the temporary credential is the same
device later included in the finalized Merkle tree.

## Provisional to permanent transition

A device arriving before the registration cutoff is added to the current
Phase 1 batch.

If it requires immediate operation before the epoch closes, Phase 2 may issue
a temporary credential.

When the finalization deadline is reached, the same queued device leaf is
included in the Merkle tree.

After successful finalization, the device receives its epoch bound inclusion
proof and transitions to `PERMANENT`.

Temporary bridging is no longer required after this transition.


# Revocation Integration

Revocation is checked across the integrated workflow rather than only during
temporary token validation.

A device may be revoked while it is still waiting in an open registration
batch.

Before finalizing a new active epoch, revoked queued devices are excluded
from the eligible registration set. This prevents a device that has already
been revoked from receiving new permanent membership in the finalized tree.

Historical proofs and current authorization are treated separately. A
historical proof can demonstrate that a device belonged to an earlier
finalized epoch, but it does not by itself prove that the device is currently
authorized.


# Automated Testing

The implementation includes automated tests for the individual phase
functionality and the integrated simulation.

The tests cover behavior including:

* device registration
* temporary token issuance
* valid provisional access
* token signature validation
* token expiry
* nonce reuse and replay protection
* stolen token rejection
* token revocation
* device revocation
* epoch timing
* registration cutoff
* batch finalization
* provisional to permanent transition
* Merkle proof generation and verification
* exclusion of revoked queued devices from a newly finalized active batch

The current test suite contains 32 automated tests.


# Performance Evaluation

Performance experiments are located in the `performance` package.

The scalability experiment evaluates device populations of:

`10, 50, 100, 250, 500, 1000`

Each experiment is repeated multiple times and the resulting measurements are
averaged.

Measurements include:

* average device registration time
* total registration time
* batch finalization time
* average proof verification time
* total proof verification time
* total processing time
* successful proof verification count

Results are stored in:

`performance_results/scalability_results.csv`

## Batch versus repeated Merkle rebuilding

A second experiment evaluates the batching design used by Phase 1.

The batch strategy collects all eligible leaves during the registration
window and constructs the Merkle tree once.

The comparison strategy reconstructs the complete Merkle tree whenever
another device leaf is added.

Both strategies use the same Phase 1 `build_tree()` implementation.

In the measured simulation, the difference increased substantially with the
number of devices. At 1000 devices, constructing the tree once took
approximately 22.51 ms, while repeatedly rebuilding it accumulated
approximately 7941.64 ms of Merkle construction time.

The measured repeated reconstruction cost at this scale was approximately
354.33 times the one time batch construction cost.

These measurements apply to the current simulation environment and should
not be interpreted as universal performance guarantees.

Comparison results are stored in:

`performance_results/batch_vs_rebuild.csv`

Generated performance graphs are stored in:

`performance_results/graphs/`