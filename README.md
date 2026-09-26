# IIoT Decentralized Identity Management Framework

This project implements a single zone decentralized identity management
framework for Industrial IoT devices.

The framework demonstrates device registration, ECC based proof of
possession, batch based Merkle identity anchoring, temporary token based
access while an epoch is open, revocation, and permanent identity
verification.

## Architecture

The implementation is divided into three main phases.

### Phase 1: Device Registration and Batch Formation

Phase 1 authenticates devices, generates and verifies ECC proof of
possession, creates device identity leaves, and queues devices into a
registration batch.

At the end of the registration window, the collected leaves are used to
construct one deterministic Merkle tree. The resulting epoch root is stored
in the trusted root registry and device specific inclusion proofs are
generated.

### Phase 2: Temporary Token Based Bridging

A device may need to operate before its registration batch has been
finalized.

Phase 2 issues a short lived fog signed credential to an already
authenticated and queued device.

Temporary access includes token signature validation, expiry checking,
nonce based replay protection, proof of possession, revocation checking,
and limited provisional authorization.

The device is not registered again. The same identity created during
Phase 1 continues through Phase 2.


## Integrated Simulation

The `simulation` package connects the phases into one continuous lifecycle.

A simulated device is created once and retains the same DID and ECC key
pair throughout the system.

Example lifecycle:

`CREATED -> QUEUED -> PROVISIONAL -> PERMANENT`

The simulation uses a virtual clock.

Current demonstration configuration:

* Epoch start: `t=0`
* Registration cutoff: `t=25`
* Epoch finalization: `t=30`

Devices arriving before the cutoff may join the current epoch.

A device requiring immediate access before finalization can receive a
temporary Phase 2 credential.

At finalization, eligible queued devices are included in the same Merkle
tree and receive permanent inclusion proofs.

## Running the Simulation

From the project root:
python run_simulation.py

## Automated Tests
Run the complete test suite with:
python -m pytest -v

## Performance Evaluation
Run the scalability and Merkle construction experiments with:
python -m performance.performance_test

## Generate Performance Graphs
After running the performance experiment:
python -m performance.generate_graphs