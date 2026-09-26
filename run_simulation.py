"""
Main entry point for the integrated IIoT identity simulation.

This file defines the simulation scenario.

Phase 1 handles:
    device authentication
    proof of possession
    registration
    leaf generation
    Merkle tree construction
    inclusion proofs

Phase 2 handles:
    temporary token issuance
    provisional access
    nonce checking
    token expiry
    token revocation

The simulation layer controls:
    device arrival times
    epoch timing
    registration cutoff
    batch finalization
    device lifecycle
"""

from __future__ import annotations

from phase1.fog_node import FogNode
from simulation.simulator import Simulator


def main() -> None:

    print(
        "\n"
        "========================================"
    )

    print(
        "IIoT DECENTRALIZED IDENTITY SIMULATION"
    )

    print(
        "========================================"
    )

    print(
        "\nStarting integrated Phase 1 and "
        "Phase 2 simulation..."
    )

    # =========================================================
    # SYSTEM SETUP
    # =========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "SYSTEM SETUP"
    )

    print(
        "========================================"
    )

    # One FogNode is created for the entire simulation.
    #
    # This is important because Phase 1 and Phase 2 must use
    # the same database and therefore the same device records.
    fog = FogNode()

    # Create the parent simulation controller.
    #
    # Epoch:
    #
    # t = 0       start
    # t = 25      registration cutoff
    # t = 30      finalization
    simulator = Simulator(
        fog=fog,
        epoch_duration=30,
        registration_cutoff=25,
    )

    print(
        "\nOne fog node created."
    )

    print(
        "Epoch 1 begins at t=0."
    )

    print(
        "Registration cutoff is t=25."
    )

    print(
        "Epoch finalization is t=30."
    )

    # =========================================================
    # DEVICE 1
    # =========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "DEVICE ARRIVAL 1"
    )

    print(
        "========================================"
    )

    simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=3,
    )

    # =========================================================
    # DEVICE 2
    # =========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "DEVICE ARRIVAL 2"
    )

    print(
        "========================================"
    )

    simulator.process_device_arrival(
        device_type="humidity sensor",
        arrival_time=7,
    )

    # =========================================================
    # DEVICE 3
    # =========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "DEVICE ARRIVAL 3"
    )

    print(
        "========================================"
    )

    simulator.process_device_arrival(
        device_type="vibration sensor",
        arrival_time=12,
    )

    # =========================================================
    # DEVICE 4
    # =========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "DEVICE ARRIVAL 4"
    )

    print(
        "========================================"
    )

    simulator.process_device_arrival(
        device_type="pressure sensor",
        arrival_time=18,
    )

    # =========================================================
    # DEVICE 5
    #
    # This device arrives while Epoch 1 is still open.
    #
    # Phase 1 authenticates and queues it normally.
    #
    # But it needs access immediately and cannot wait until
    # t=30 for its permanent Merkle proof.
    #
    # Therefore Phase 2 provides temporary bridging.
    # =========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "DEVICE ARRIVAL 5"
    )

    print(
        "========================================"
    )

    print(
        "\nA temperature sensor arrives and "
        "requires immediate resource access."
    )

    provisional_device = (
        simulator.process_device_arrival(
            device_type="temperature sensor",
            arrival_time=20,
            needs_immediate_access=True,
        )
    )

    print(
        "\nPhase 2 demonstration device:"
    )

    print(
        f"DID: {provisional_device.did}"
    )

    print(
        f"Current state: "
        f"{provisional_device.state}"
    )

    # =========================================================
    # EPOCH REMAINS OPEN
    # =========================================================

    simulator.advance_to(
        24
    )

    print(
        "\n"
        "========================================"
    )

    print(
        "EPOCH STILL OPEN"
    )

    print(
        "========================================"
    )

    simulator.epoch_manager.finalize_if_due()

    print(
        "\nThe Phase 2 device is still operating "
        "using provisional access."
    )

    print(
        "Its permanent Merkle proof does not "
        "exist yet."
    )

    # =========================================================
    # REGISTRATION CUTOFF
    # =========================================================

    simulator.reach_registration_cutoff()

    # =========================================================
    # OPTIONAL LATE DEVICE
    #
    # This demonstrates that a device arriving after t=25
    # cannot change Epoch 1.
    #
    # It is queued for Epoch 2 instead.
    # =========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "LATE DEVICE ARRIVAL"
    )

    print(
        "========================================"
    )

    print(
        "\nA flow sensor arrives after the "
        "Epoch 1 registration cutoff."
    )

    late_device = (
        simulator.process_device_arrival(
            device_type="flow sensor",
            arrival_time=27,
        )
    )

    print(
        f"\nLate device DID: "
        f"{late_device.did}"
    )

    print(
        "It must not be included in the "
        "Epoch 1 Merkle tree."
    )

    # =========================================================
    # FINALIZE EPOCH 1
    # =========================================================

    print(
        "\nEpoch 1 will now reach its "
        "finalization deadline."
    )

    epoch1_result = (
        simulator.finalize_current_epoch()
    )

    # =========================================================
    # VERIFY THE MAIN SIMULATION RESULT
    # =========================================================

    if epoch1_result is not None:

        print(
            "\n"
            "========================================"
        )

        print(
            "SIMULATION CONSISTENCY CHECK"
        )

        print(
            "========================================"
        )

        phase2_in_epoch1 = (
            provisional_device.did
            in epoch1_result.proofs
        )

        late_device_in_epoch1 = (
            late_device.did
            in epoch1_result.proofs
        )

        print(
            f"\nPhase 2 device included in "
            f"Epoch 1: "
            f"{phase2_in_epoch1}"
        )

        print(
            f"Late device included in "
            f"Epoch 1: "
            f"{late_device_in_epoch1}"
        )

        print(
            f"Phase 2 device final state: "
            f"{provisional_device.state}"
        )

        print(
            f"Late device current state: "
            f"{late_device.state}"
        )

        if (
            phase2_in_epoch1
            and not late_device_in_epoch1
        ):

            print(
                "\nEpoch timing behaved correctly."
            )

            print(
                "The device arriving at t=20 was "
                "registered before cutoff and became "
                "a permanent Epoch 1 member."
            )

            print(
                "The device arriving at t=27 missed "
                "the cutoff and was not allowed to "
                "change the finalized Epoch 1 tree."
            )

    # =========================================================
    # FINAL SUMMARY
    # =========================================================

    simulator.print_summary()

    print(
        "\n"
        "========================================"
    )

    print(
        "SIMULATION COMPLETE"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()