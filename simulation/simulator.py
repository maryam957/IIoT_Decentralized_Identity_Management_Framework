"""Integrated Phase 1 and Phase 2 IIoT simulation controller."""

from __future__ import annotations

import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from phase1.merkle import verify_proof
from phase2.token_service import TokenService

from .clock import SimulationClock
from .device_agent import DeviceAgent
from .epoch_manager import EpochConfiguration, EpochManager


class Simulator:
    """
    Parent simulation controller.

    The simulator coordinates:

        device arrivals
        Phase 1 registration
        epoch timing
        Phase 2 temporary bridging
        registration cutoff
        batch finalization
        transition from provisional to permanent identity

    Security functionality remains inside Phase 1 and Phase 2.
    """

    def __init__(
        self,
        fog,
        epoch_duration: int = 30,
        registration_cutoff: int = 25,
    ):

        self.fog = fog

        # -----------------------------------------------------
        # SIMULATION INFRASTRUCTURE
        # -----------------------------------------------------

        self.clock = SimulationClock(
            start_time=0
        )

        config = EpochConfiguration(
            duration=epoch_duration,
            registration_cutoff=registration_cutoff,
        )

        self.epoch_manager = EpochManager(
            fog=self.fog,
            clock=self.clock,
            config=config,
        )

        # -----------------------------------------------------
        # PHASE 2 SERVICE
        # -----------------------------------------------------

        self.token_service = TokenService(
            self.fog.connection
        )

        # All devices created during this simulation.
        self.devices: list[DeviceAgent] = []

        # Store test results for final summary.
        self.phase2_results = {
            "temporary_token_issued": False,
            "valid_provisional_access": False,
            "replay_blocked": False,
            "unauthorized_blocked": False,
            "stolen_token_blocked": False,
            "expired_token_blocked": False,
            "revoked_token_blocked": False,
            "permanent_inclusion_verified": False,
        }

        # Track the device used to demonstrate Phase 2.
        self.provisional_agent: DeviceAgent | None = None

    # =========================================================
    # TIME
    # =========================================================

    def advance_to(
        self,
        target_time: int,
    ) -> None:
        """Advance the virtual simulation clock."""

        self.clock.advance_to(
            target_time
        )

    # =========================================================
    # DEVICE ARRIVAL
    # =========================================================

    def create_device(
        self,
        device_type: str,
        arrival_time: int,
        needs_immediate_access: bool = False,
    ) -> DeviceAgent:
        """
        Create one simulated device.

        The actual Phase 1 Device object is created once inside
        DeviceAgent and is reused throughout its lifecycle.
        """

        agent = DeviceAgent(
            device_type=device_type,
            arrival_time=arrival_time,
            needs_immediate_access=needs_immediate_access,
        )

        self.devices.append(
            agent
        )

        return agent

    def process_device_arrival(
        self,
        device_type: str,
        arrival_time: int,
        needs_immediate_access: bool = False,
    ) -> DeviceAgent:
        """
        Process a device arrival at a particular simulated time.

        Flow:

            create device once
            advance clock
            classify epoch
            call Phase 1 registration
            optionally call Phase 2
        """

        # Device must not arrive in the simulated past.
        if arrival_time < self.clock.now:
            raise ValueError(
                "device arrival cannot occur in the past"
            )

        self.advance_to(
            arrival_time
        )

        agent = self.create_device(
            device_type=device_type,
            arrival_time=arrival_time,
            needs_immediate_access=needs_immediate_access,
        )

        agent.display_arrival()

        # -----------------------------------------------------
        # EPOCH DECISION + PHASE 1
        # -----------------------------------------------------

        registration = (
            self.epoch_manager.register_agent(
                agent
            )
        )

        # Device arrived after registration cutoff.
        if registration is None:

            print(
                f"{agent.device_type.title()} arrived "
                f"after the registration cutoff."
            )

            print(
                f"Device will wait for Epoch "
                f"{self.epoch_manager.epoch_number + 1}."
            )

            return agent

        print(
            f"{agent.device_type.title()} "
            f"queued in {registration.batch_id}."
        )

        # -----------------------------------------------------
        # PHASE 2
        # -----------------------------------------------------

        if needs_immediate_access:

            self.provisional_agent = agent

            self.activate_temporary_bridging(
                agent
            )

        return agent

    # =========================================================
    # PHASE 2 TOKEN BRIDGING
    # =========================================================

    def activate_temporary_bridging(
        self,
        agent: DeviceAgent,
    ) -> None:
        """
        Issue a temporary credential for a device that has
        completed Phase 1 but has no Merkle proof yet.
        """

        if agent.state != "QUEUED":
            raise RuntimeError(
                "temporary bridging requires a device "
                "already queued by Phase 1"
            )

        print(
            "\n"
            "========================================"
        )

        print(
            "PHASE 2 TEMPORARY TOKEN BRIDGING"
        )

        print(
            "========================================"
        )

        print(
            f"\nDevice DID: {agent.did}"
        )

        print(
            f"Current state: {agent.state}"
        )

        print(
            "Permanent Merkle proof available: False"
        )

        print(
            "\nThe device needs immediate access before "
            "the epoch is finalized."
        )

        print(
            "Phase 2 therefore issues a limited "
            "temporary credential."
        )

        # IMPORTANT:
        # We pass only the DID.
        #
        # TokenService retrieves the existing public key,
        # metadata and batch from the Phase 1 database.
        token = self.token_service.issue_token(
            agent.did
        )

        agent.assign_temporary_token(
            token
        )

        self.phase2_results[
            "temporary_token_issued"
        ] = True

        print(
            "\nTemporary fog signed token issued."
        )

        print(
            f"Device state: {agent.state}"
        )

        print(
            "Permanent Merkle proof available: False"
        )

        # Run Phase 2 security demonstrations.
        self.run_phase2_tests(
            agent
        )

    # =========================================================
    # SIGN REQUEST NONCE
    # =========================================================

    @staticmethod
    def sign_nonce(
        agent: DeviceAgent,
        nonce: str,
    ) -> bytes:
        """
        Sign a fresh resource request nonce using the same
        ECC private key created for the device in Phase 1.
        """

        return agent.private_key.sign(
            nonce.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )

    # =========================================================
    # PHASE 2 SECURITY TESTS
    # =========================================================

    def run_phase2_tests(
        self,
        agent: DeviceAgent,
    ) -> None:
        """Demonstrate the required Phase 2 security checks."""

        token = agent.temporary_token

        if token is None:
            raise RuntimeError(
                "device does not have a temporary token"
            )

        # -----------------------------------------------------
        # TEST 1
        # VALID PROVISIONAL ACCESS
        # -----------------------------------------------------

        print(
            "\n--- Test 1: Valid Provisional Access ---"
        )

        nonce = (
            self.token_service.create_nonce()
        )

        signature = self.sign_nonce(
            agent,
            nonce,
        )

        valid_result = (
            self.token_service.request_resource(
                token,
                nonce,
                signature,
                "temperature_readings",
                "WRITE",
            )
        )

        self.phase2_results[
            "valid_provisional_access"
        ] = valid_result

        print(
            f"Access result: {valid_result}"
        )

        # -----------------------------------------------------
        # TEST 2
        # REPLAY ATTACK
        # -----------------------------------------------------

        print(
            "\n--- Test 2: Replay Attack ---"
        )

        print(
            "Reusing the same nonce and signature..."
        )

        replay_result = (
            self.token_service.request_resource(
                token,
                nonce,
                signature,
                "temperature_readings",
                "WRITE",
            )
        )

        self.phase2_results[
            "replay_blocked"
        ] = not replay_result

        print(
            f"Replay result: {replay_result}"
        )

        # -----------------------------------------------------
        # TEST 3
        # UNAUTHORIZED PROVISIONAL ACCESS
        # -----------------------------------------------------

        print(
            "\n--- Test 3: Unauthorized "
            "Provisional Access ---"
        )

        unauthorized_nonce = (
            self.token_service.create_nonce()
        )

        unauthorized_signature = (
            self.sign_nonce(
                agent,
                unauthorized_nonce,
            )
        )

        unauthorized_result = (
            self.token_service.request_resource(
                token,
                unauthorized_nonce,
                unauthorized_signature,
                "production_line",
                "STOP",
            )
        )

        self.phase2_results[
            "unauthorized_blocked"
        ] = not unauthorized_result

        print(
            f"Unauthorized access result: "
            f"{unauthorized_result}"
        )

        # -----------------------------------------------------
        # TEST 4
        # STOLEN TOKEN
        # -----------------------------------------------------

        print(
            "\n--- Test 4: Stolen Token Attack ---"
        )

        print(
            "Attacker has the genuine temporary token "
            "but does not have the legitimate device "
            "private key."
        )

        attacker = DeviceAgent(
            device_type=agent.device_type,
            arrival_time=self.clock.now,
        )

        stolen_nonce = (
            self.token_service.create_nonce()
        )

        attacker_signature = (
            self.sign_nonce(
                attacker,
                stolen_nonce,
            )
        )

        stolen_result = (
            self.token_service.request_resource(
                token,
                stolen_nonce,
                attacker_signature,
                "temperature_readings",
                "WRITE",
            )
        )

        self.phase2_results[
            "stolen_token_blocked"
        ] = not stolen_result

        print(
            f"Stolen token result: "
            f"{stolen_result}"
        )

        # -----------------------------------------------------
        # TEST 5
        # EXPIRED TOKEN
        # -----------------------------------------------------

        print(
            "\n--- Test 5: Expired Token ---"
        )

        print(
            "Issuing a demonstration token with "
            "a 2 second lifetime..."
        )

        expiring_token = (
            self.token_service.issue_token(
                agent.did,
                lifetime_seconds=2,
            )
        )

        print(
            "Waiting for demonstration token "
            "to expire..."
        )

        # TokenService uses real cryptographic expiry time.
        # Only this security test waits in real time.
        time.sleep(3)

        expiry_nonce = (
            self.token_service.create_nonce()
        )

        expiry_signature = (
            self.sign_nonce(
                agent,
                expiry_nonce,
            )
        )

        expired_result = (
            self.token_service.request_resource(
                expiring_token,
                expiry_nonce,
                expiry_signature,
                "temperature_readings",
                "WRITE",
            )
        )

        self.phase2_results[
            "expired_token_blocked"
        ] = not expired_result

        print(
            f"Expired token result: "
            f"{expired_result}"
        )

        # -----------------------------------------------------
        # TEST 6
        # TOKEN REVOCATION
        # -----------------------------------------------------

        print(
            "\n--- Test 6: Revoked Token ---"
        )

        self.token_service.revoke_token(
            token
        )

        revoked_nonce = (
            self.token_service.create_nonce()
        )

        revoked_signature = (
            self.sign_nonce(
                agent,
                revoked_nonce,
            )
        )

        revoked_result = (
            self.token_service.request_resource(
                token,
                revoked_nonce,
                revoked_signature,
                "temperature_readings",
                "WRITE",
            )
        )

        self.phase2_results[
            "revoked_token_blocked"
        ] = not revoked_result

        print(
            f"Revoked token result: "
            f"{revoked_result}"
        )

    # =========================================================
    # REGISTRATION CUTOFF
    # =========================================================

    def reach_registration_cutoff(
        self,
    ) -> None:
        """Advance the simulation to the registration cutoff."""

        cutoff = (
            self.epoch_manager.cutoff_time
        )

        if self.clock.now < cutoff:
            self.advance_to(
                cutoff
            )

        print(
            "\n"
            "========================================"
        )

        print(
            "REGISTRATION CUTOFF REACHED"
        )

        print(
            "========================================"
        )

        self.epoch_manager.print_epoch_status()

        print(
            f"\nEpoch "
            f"{self.epoch_manager.epoch_number} "
            f"no longer accepts new devices."
        )

        print(
            "Devices already queued remain eligible "
            "for finalization."
        )

    # =========================================================
    # EPOCH FINALIZATION
    # =========================================================

    def finalize_current_epoch(
        self,
    ):
        """
        Advance to the epoch deadline and ask EpochManager
        to call Phase 1 batch finalization.
        """

        deadline = (
            self.epoch_manager.finalization_time
        )

        if self.clock.now < deadline:
            self.advance_to(
                deadline
            )

        print(
            "\n"
            "========================================"
        )

        print(
            "EPOCH FINALIZATION DEADLINE"
        )

        print(
            "========================================"
        )

        finalized_epoch_number = (
            self.epoch_manager.epoch_number
        )

        result = (
            self.epoch_manager.finalize_if_due(
                 is_revoked=self.token_service.is_device_revoked,
            )
        )

        if result is None:
            return None

        print(
            f"\nEpoch ID: "
            f"{result.epoch_id}"
        )

        print(
            f"Merkle root: "
            f"{result.root}"
        )

        print(
            f"Devices included in finalized tree: "
            f"{len(result.proofs)}"
        )

        self.display_finalized_membership(
            result
        )

        # Convert registered agents from QUEUED or
        # PROVISIONAL to PERMANENT.
        self.update_finalized_devices(
            result,
        )

        # Devices that arrived after cutoff can now
        # enter the newly opened epoch.
        self.process_next_epoch_queue()

        return result

    # =========================================================
    # FINALIZED MEMBERSHIP
    # =========================================================

    def display_finalized_membership(
        self,
        result,
    ) -> None:
        """Display DIDs included in the finalized Merkle tree."""

        print(
            "\n--- Finalized Merkle Membership ---"
        )

        for index, did in enumerate(
            result.proofs.keys(),
            start=1,
        ):

            marker = ""

            if (
                self.provisional_agent is not None
                and did == self.provisional_agent.did
            ):
                marker = (
                    "  <-- previously provisional device"
                )

            print(
                f"  {index}. {did}{marker}"
            )

    # =========================================================
    # PROVISIONAL TO PERMANENT
    # =========================================================

    def update_finalized_devices(
        self,
        result,
    ) -> None:
        """
        Give finalized devices their permanent inclusion proofs.

        This proves that the same Phase 2 device is now part
        of the Phase 1 finalized Merkle tree.
        """

        for agent in self.devices:

            if agent.did not in result.proofs:
                continue

            proof = result.proofs[
                agent.did
            ]

            # Verify the Phase 1 proof before changing state.
            proof_valid = verify_proof(
                bytes.fromhex(
                    proof.leaf_hash
                ),
                proof.proof,
                result.root,
            )

            if not proof_valid:

                print(
                    f"[PERMANENT_TRANSITION] "
                    f"did={agent.did} "
                    f"result=FAILED "
                    f"reason=Merkle proof invalid"
                )

                continue

            previous_state = agent.state

            agent.mark_permanent(
                epoch_id=result.epoch_id,
                proof=proof,
            )

            print(
                f"\n[PERMANENT_TRANSITION] "
                f"did={agent.did} "
                f"{previous_state} -> PERMANENT"
            )

            # Special reporting for Phase 2 device.
            if (
                self.provisional_agent is not None
                and agent.did
                == self.provisional_agent.did
            ):

                self.phase2_results[
                    "permanent_inclusion_verified"
                ] = True

                self.display_phase2_transition(
                    agent,
                    proof,
                    result.root,
                )

    def display_phase2_transition(
        self,
        agent: DeviceAgent,
        proof,
        root: str,
    ) -> None:
        """
        Display proof that the temporary Phase 2 device became
        a permanent Merkle member.
        """

        print(
            "\n"
            "========================================"
        )

        print(
            "PROVISIONAL TO PERMANENT TRANSITION"
        )

        print(
            "========================================"
        )

        print(
            f"\nDevice DID: {agent.did}"
        )

        print(
            f"Epoch ID: {agent.epoch_id}"
        )

        print(
            f"Merkle root: {root}"
        )

        print(
            "Permanent proof verification: True"
        )

        print(
            "\nMerkle inclusion proof:"
        )

        for index, step in enumerate(
            proof.proof,
            start=1,
        ):

            print(
                f"  Step {index}: "
                f"position={step['position']}, "
                f"sibling={step['sibling']}"
            )

        print(
            "\nDevice lifecycle:"
        )

        print(
            "CREATED"
        )

        print(
            "   -> QUEUED"
        )

        print(
            "   -> PROVISIONAL"
        )

        print(
            "   -> PERMANENT"
        )

        print(
            "\nThe same device that used temporary "
            "Phase 2 access is now included in the "
            "finalized Phase 1 Merkle tree."
        )

        print(
            "Temporary bridging is no longer required."
        )

    # =========================================================
    # NEXT EPOCH
    # =========================================================

    def process_next_epoch_queue(
        self,
    ) -> None:
        """
        Register devices that arrived after the previous
        registration cutoff into the newly opened epoch.
        """

        waiting = (
            self.epoch_manager.release_next_epoch_queue()
        )

        if not waiting:
            return

        print(
            "\n"
            "========================================"
        )

        print(
            "NEXT EPOCH WAITING DEVICES"
        )

        print(
            "========================================"
        )

        for agent in waiting:

            print(
                f"\nRegistering waiting device: "
                f"{agent.did}"
            )

            registration = (
                self.epoch_manager.register_agent(
                    agent
                )
            )

            if registration is not None:

                print(
                    f"Device entered "
                    f"{registration.batch_id}."
                )

                # If the late device required immediate access,
                # temporary bridging can now begin after its
                # Phase 1 authentication succeeds.
                if agent.needs_immediate_access:

                    self.provisional_agent = agent

                    self.activate_temporary_bridging(
                        agent
                    )

    # =========================================================
    # SUMMARY
    # =========================================================

    def print_summary(
        self,
    ) -> None:
        """Display Phase 1 and Phase 2 simulation results."""

        print(
            "\n"
            "========================================"
        )

        print(
            "PHASE 1 + PHASE 2 SIMULATION SUMMARY"
        )

        print(
            "========================================"
        )

        print(
            f"Devices created once: "
            f"{len(self.devices)}"
        )

        if self.provisional_agent is not None:

            print(
                f"Phase 2 device DID: "
                f"{self.provisional_agent.did}"
            )

            print(
                f"Final Phase 2 device state: "
                f"{self.provisional_agent.state}"
            )

        print(
            f"Temporary token issued: "
            f"{self.phase2_results['temporary_token_issued']}"
        )

        print(
            f"Valid provisional access: "
            f"{self.phase2_results['valid_provisional_access']}"
        )

        print(
            f"Replay attack blocked: "
            f"{self.phase2_results['replay_blocked']}"
        )

        print(
            f"Unauthorized provisional access blocked: "
            f"{self.phase2_results['unauthorized_blocked']}"
        )

        print(
            f"Stolen token blocked: "
            f"{self.phase2_results['stolen_token_blocked']}"
        )

        print(
            f"Expired token blocked: "
            f"{self.phase2_results['expired_token_blocked']}"
        )

        print(
            f"Revoked token blocked: "
            f"{self.phase2_results['revoked_token_blocked']}"
        )

        print(
            f"Permanent Merkle inclusion verified: "
            f"{self.phase2_results['permanent_inclusion_verified']}"
        )