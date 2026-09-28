# IIoT Decentralized Identity Management Framework

This project implements a single-zone decentralized identity management
framework for Industrial IoT devices.

The framework demonstrates the complete device identity lifecycle:

- Device registration and authentication
- ECC-based proof of possession
- Batch-based Merkle identity anchoring
- Temporary token-based access while an epoch is open
- Permanent identity verification
- Resource authorization
- Device/token revocation
- Security attack testing
- Performance and scalability evaluation
- Batch versus individual registration comparison

The implementation uses one fog node and multiple simulated IIoT devices.

---

## Architecture

The implementation is divided into three main phases.

### Phase 1: Device Registration and Batch Formation

Phase 1 authenticates devices using a pre-shared key (PSK), generates
DIDs and ECC key pairs, and verifies proof of possession.

Each registered device produces an identity leaf:

`H(DID || PublicKey)`

Devices are collected into an open registration batch instead of
rebuilding the Merkle tree after every registration.

At the end of the registration window:

1. Device leaves are collected.
2. Leaves are deterministically sorted.
3. A Merkle tree is constructed.
4. A single epoch root is generated.
5. The root is stored in the trusted root registry.
6. A device-specific inclusion proof is generated for every device.

---

### Phase 2: Temporary Token-Based Bridging

A device may need to operate before its registration batch has been
finalized.

Phase 2 issues a short-lived fog-signed temporary token to an
authenticated and queued device.

The token contains identity and authorization information including:

- DID
- Public key
- Role/metadata
- Batch information
- Issue time
- Expiry time

Temporary access includes:

- Token signature validation
- Expiry checking
- Fresh nonce validation
- Replay/nonce reuse protection
- Device proof of possession
- Token/device revocation checking
- Limited provisional authorization

The same device identity created during Phase 1 continues through
Phase 2.

---

### Phase 3: Permanent Identity Verification and Authorization

After a registration batch has been finalized, the device can prove its
permanent identity using its epoch-bound Merkle inclusion proof.

Phase 3 performs:

1. DID and public key verification
2. Leaf recomputation
3. Trusted epoch root retrieval
4. Merkle inclusion proof verification
5. Current revocation/status checking
6. Resource authorization
7. Clear ALLOW or DENY decision

Identity verification and authorization are kept separate.

A valid historical Merkle proof demonstrates that the device belonged
to a particular finalized epoch. It does not automatically mean that
the device is currently authorized.

The authorization layer applies role/resource/operation policies.

Example:

- A temperature sensor may read or write temperature data.
- A temperature sensor must not be allowed to perform an unrelated
  production-control operation.

---

## Revocation

The framework supports immediate device and token revocation.

Revocation checks are performed during resource-access and identity
authorization flows.

A revoked device is also excluded from the active registration set
before the next batch is finalized.

This allows the system to distinguish between:

- Historical membership in a previous epoch
- Current authorization status

Therefore, an old valid Merkle proof can remain historically valid while
the device is still denied current access because it has been revoked.

---

## Integrated Simulation

The `simulation` package connects the phases into one continuous
lifecycle.

A simulated device is created once and retains the same DID and ECC key
pair throughout the system.

Example lifecycle:

`CREATED -> QUEUED -> PROVISIONAL -> PERMANENT`

The simulation uses a virtual clock.

Current demonstration configuration:

- Epoch start: `t=0`
- Registration cutoff: `t=25`
- Epoch finalization: `t=30`

Devices arriving before the cutoff may join the current epoch.

A device requiring immediate access before finalization can receive a
temporary Phase 2 credential.

At finalization, eligible queued devices are included in the same
Merkle tree and receive permanent inclusion proofs.

---

## Project Structure

```text
IIoT_Decentralized_Identity_Management_Framework/
│
├── phase1/
│   ├── device.py
│   ├── fog_node.py
│   └── merkle.py
│
├── phase2/
│   ├── token_service.py
│   └── provisional_access.py
│
├── phase3/
│   ├── __init__.py
│   ├── verification.py
│   └── authorization.py
│
├── performance/
│   ├── phase3_performance.py
│   ├── phase3_graphs.py
│   └── batch_vs_individual.py
│
├── performance_results/
│   ├── phase3_results.csv
│   ├── batch_vs_individual.csv
│   └── graphs/
│
├── tests/
│   ├── test_phase3.py
│   └── test_phase3_security.py
│
├── simulation/
│
└── run_simulation.py
