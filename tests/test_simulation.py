"""
Automated integration tests for the IIoT simulation.

Tests Phase 1 and Phase 2 integration, epoch timing,
device lifecycle, registration cutoff, finalization,
temporary bridging, and permanent Merkle inclusion.
"""

import pytest

from phase1.fog_node import FogNode
from simulation.simulator import Simulator


# ============================================================
# FIXTURE
# ============================================================


@pytest.fixture
def system():

    fog = FogNode()

    simulator = Simulator(
        fog=fog,
        epoch_duration=30,
        registration_cutoff=25,
    )

    yield fog, simulator

    if hasattr(fog, "close"):
        fog.close()


# ============================================================
# TEST 1
# EPOCH STARTS OPEN
# ============================================================


def test_epoch_starts_with_registration_open(system):

    fog, simulator = system

    assert simulator.clock.now == 0

    assert simulator.epoch_manager.epoch_number == 1

    assert (
        simulator.epoch_manager.registration_open()
        is True
    )

    assert (
        simulator.epoch_manager.state()
        == "REGISTRATION_OPEN"
    )


# ============================================================
# TEST 2
# DEVICE BEFORE CUTOFF ENTERS CURRENT EPOCH
# ============================================================


def test_device_before_cutoff_enters_current_epoch(system):

    fog, simulator = system

    agent = simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=3,
    )

    assert agent is not None

    assert agent.arrival_time == 3

    assert simulator.clock.now == 3

    assert agent.state == "QUEUED"

    # DeviceAgent stores registration information directly.
    assert agent.batch_id is not None
    assert agent.leaf_hash is not None


# ============================================================
# TEST 3
# MULTIPLE DEVICES SHARE SAME OPEN EPOCH
# ============================================================


def test_multiple_devices_share_same_epoch(system):

    fog, simulator = system

    arrival_schedule = [
        (3, "pressure sensor"),
        (7, "humidity sensor"),
        (12, "vibration sensor"),
        (18, "pressure sensor"),
        (20, "temperature sensor"),
    ]

    agents = []

    for arrival_time, device_type in arrival_schedule:

        agent = simulator.process_device_arrival(
            device_type=device_type,
            arrival_time=arrival_time,
        )

        agents.append(agent)

    assert len(simulator.devices) == 5

    # Every DeviceAgent stores its assigned batch directly.
    batch_ids = {
        agent.batch_id
        for agent in agents
    }

    assert None not in batch_ids

    # All five devices must belong to one batch.
    assert len(batch_ids) == 1

    assert all(
        agent.state == "QUEUED"
        for agent in agents
    )


# ============================================================
# TEST 4
# REGISTRATION CLOSES AT CUTOFF
# ============================================================


def test_registration_closes_at_cutoff(system):

    fog, simulator = system

    simulator.advance_to(25)

    assert (
        simulator.epoch_manager.registration_open()
        is False
    )

    assert (
        simulator.epoch_manager.state()
        == "REGISTRATION_CLOSED"
    )


# ============================================================
# TEST 5
# LATE DEVICE WAITS FOR NEXT EPOCH
# ============================================================


def test_late_device_waits_for_next_epoch(system):

    fog, simulator = system

    late_agent = simulator.process_device_arrival(
        device_type="humidity sensor",
        arrival_time=27,
    )

    assert late_agent is not None

    # It has not completed Phase 1 registration yet.
    assert late_agent.batch_id is None
    assert late_agent.leaf_hash is None

    assert late_agent.state != "PERMANENT"


# ============================================================
# TEST 6
# EPOCH DOES NOT FINALIZE EARLY
# ============================================================


def test_epoch_does_not_finalize_before_deadline(system):

    fog, simulator = system

    simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=10,
    )

    simulator.advance_to(29)

    result = (
        simulator
        .epoch_manager
        .finalize_if_due()
    )

    assert result is None

    assert simulator.epoch_manager.epoch_number == 1


# ============================================================
# TEST 7
# EPOCH FINALIZES AT DEADLINE
# ============================================================


def test_epoch_finalizes_at_deadline(system):

    fog, simulator = system

    agent = simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=10,
    )

    result = simulator.finalize_current_epoch()

    assert result is not None

    assert result.epoch_id == 1

    assert result.root is not None

    assert agent.did in result.proofs


# ============================================================
# TEST 8
# DEVICE BECOMES PERMANENT
# ============================================================


def test_device_becomes_permanent_after_finalization(system):

    fog, simulator = system

    agent = simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=10,
    )

    assert agent.state == "QUEUED"

    simulator.finalize_current_epoch()

    assert agent.state == "PERMANENT"

    assert agent.epoch_id == 1

    assert agent.permanent_proof is not None

    assert agent.has_permanent_identity is True


# ============================================================
# TEST 9
# PHASE 2 DEVICE GETS TEMPORARY TOKEN
# ============================================================


def test_immediate_access_device_becomes_provisional(
    system,
    monkeypatch,
):

    fog, simulator = system

    # Security behaviour is already tested independently
    # in test_phase2.py.
    monkeypatch.setattr(
        simulator,
        "run_phase2_tests",
        lambda agent: None,
    )

    agent = simulator.process_device_arrival(
        device_type="temperature sensor",
        arrival_time=20,
        needs_immediate_access=True,
    )

    assert agent.state == "PROVISIONAL"

    assert agent.temporary_token is not None

    assert agent.has_temporary_access is True

    assert simulator.provisional_agent is agent

    assert (
        simulator.phase2_results[
            "temporary_token_issued"
        ]
        is True
    )


# ============================================================
# TEST 10
# SAME PROVISIONAL DEVICE ENTERS FINAL MERKLE TREE
# ============================================================


def test_provisional_device_is_in_finalized_tree(
    system,
    monkeypatch,
):

    fog, simulator = system

    monkeypatch.setattr(
        simulator,
        "run_phase2_tests",
        lambda agent: None,
    )

    simulator.process_device_arrival(
        "pressure sensor",
        3,
    )

    simulator.process_device_arrival(
        "humidity sensor",
        7,
    )

    simulator.process_device_arrival(
        "vibration sensor",
        12,
    )

    provisional_agent = (
        simulator.process_device_arrival(
            device_type="temperature sensor",
            arrival_time=20,
            needs_immediate_access=True,
        )
    )

    assert provisional_agent.state == "PROVISIONAL"

    provisional_did = provisional_agent.did

    result = simulator.finalize_current_epoch()

    # The SAME device that received the temporary token
    # must now exist in the permanent Merkle tree.
    assert provisional_did in result.proofs

    assert provisional_agent.state == "PERMANENT"

    assert provisional_agent.permanent_proof is not None

    assert provisional_agent.has_permanent_identity is True

    assert (
        simulator.phase2_results[
            "permanent_inclusion_verified"
        ]
        is True
    )


# ============================================================
# TEST 11
# PHASE 2 DOES NOT REGENERATE DEVICE IDENTITY
# ============================================================


def test_phase2_reuses_same_device_identity(
    system,
    monkeypatch,
):

    fog, simulator = system

    monkeypatch.setattr(
        simulator,
        "run_phase2_tests",
        lambda agent: None,
    )

    agent = simulator.process_device_arrival(
        device_type="temperature sensor",
        arrival_time=20,
        needs_immediate_access=True,
    )

    # Save the identity before finalization.
    did_before = agent.did
    public_key_before = agent.public_key_bytes
    device_object_before = agent.device

    simulator.finalize_current_epoch()

    # Same DID.
    assert agent.did == did_before

    # Same public key.
    assert (
        agent.public_key_bytes
        == public_key_before
    )

    # Same underlying Phase 1 Device object.
    assert agent.device is device_object_before

    assert agent.state == "PERMANENT"


# ============================================================
# TEST 12
# NEXT EPOCH STARTS AFTER FINALIZATION
# ============================================================


def test_next_epoch_starts_after_finalization(system):

    fog, simulator = system

    simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=10,
    )

    simulator.finalize_current_epoch()

    assert simulator.epoch_manager.epoch_number == 2

    assert simulator.epoch_manager.epoch_start == 30

    assert simulator.epoch_manager.cutoff_time == 55

    assert (
        simulator.epoch_manager.finalization_time
        == 60
    )


# ============================================================
# TEST 13
# LATE DEVICE ENTERS NEXT EPOCH
# ============================================================


def test_late_device_enters_next_epoch(system):

    fog, simulator = system

    epoch_one_agent = (
        simulator.process_device_arrival(
            device_type="pressure sensor",
            arrival_time=10,
        )
    )

    epoch_one_batch = epoch_one_agent.batch_id

    # Arrives after cutoff at t=25.
    late_agent = (
        simulator.process_device_arrival(
            device_type="humidity sensor",
            arrival_time=27,
        )
    )

    # Not registered in Epoch 1.
    assert late_agent.batch_id is None
    assert late_agent.leaf_hash is None

    result = simulator.finalize_current_epoch()

    assert result is not None

    # Waiting device should now be processed
    # into the newly opened Epoch 2 batch.
    assert late_agent.batch_id is not None
    assert late_agent.leaf_hash is not None

    assert late_agent.batch_id != epoch_one_batch

    assert late_agent.state == "QUEUED"


# ============================================================
# TEST 14
# LATE DEVICE NOT INCLUDED IN PREVIOUS EPOCH
# ============================================================


def test_late_device_not_in_previous_epoch(system):

    fog, simulator = system

    valid_agent = simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=10,
    )

    late_agent = simulator.process_device_arrival(
        device_type="humidity sensor",
        arrival_time=27,
    )

    result = simulator.finalize_current_epoch()

    assert valid_agent.did in result.proofs

    # Late device belongs to Epoch 2,
    # therefore it must not be in Epoch 1 proof set.
    assert late_agent.did not in result.proofs


# ============================================================
# TEST 15
# FINALIZED DEVICE HAS MEMBERSHIP PROOF
# ============================================================


def test_permanent_device_has_membership_proof(system):

    fog, simulator = system

    agent = simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=10,
    )

    result = simulator.finalize_current_epoch()

    assert agent.did in result.proofs

    assert agent.permanent_proof is not None

    assert agent.epoch_id == result.epoch_id

    assert agent.has_permanent_identity is True

# ============================================================
# TEST 16
# REVOKED QUEUED DEVICE EXCLUDED FROM FINALIZED ACTIVE BATCH
# ============================================================


def test_revoked_queued_device_excluded_from_finalized_batch(
    system,
):

    fog, simulator = system

    # Device 1 remains legitimate.
    valid_agent = simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=5,
    )

    # Device 2 initially registers normally.
    revoked_agent = simulator.process_device_arrival(
        device_type="temperature sensor",
        arrival_time=10,
    )

    assert valid_agent.state == "QUEUED"
    assert revoked_agent.state == "QUEUED"

    assert valid_agent.batch_id is not None
    assert revoked_agent.batch_id is not None

    # Revoke Device 2 before Epoch 1 finalizes.
    simulator.token_service.revoke_device(
        revoked_agent.did
    )

    assert (
        simulator.token_service.is_device_revoked(
            revoked_agent.did
        )
        is True
    )

    # Finalize Epoch 1.
    result = simulator.finalize_current_epoch()

    # Legitimate device should be included.
    assert valid_agent.did in result.proofs

    # Revoked device should not be part of
    # the new finalized active registration set.
    assert revoked_agent.did not in result.proofs