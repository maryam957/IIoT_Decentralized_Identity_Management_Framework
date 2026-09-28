"""Epoch lifecycle management for the IIoT simulation."""

from __future__ import annotations

from dataclasses import dataclass

from phase1.fog_node import FogNode


@dataclass
class EpochConfiguration:
    """
    Timing configuration for registration epochs.

    Default simulation:

        t = 0
            Epoch starts.

        t = 0 to 24
            Devices may join the current epoch.

        t = 25
            Registration cutoff is reached.

        t = 25 to 29
            No new devices may enter the current epoch.

        t = 30
            Current batch is finalized and the Merkle tree
            is constructed.

        t = 30
            Next epoch begins.
    """

    duration: int = 30
    registration_cutoff: int = 25

    def __post_init__(self) -> None:

        if self.duration <= 0:
            raise ValueError(
                "epoch duration must be positive"
            )

        if not (
            0 < self.registration_cutoff < self.duration
        ):
            raise ValueError(
                "registration cutoff must occur "
                "before epoch finalization"
            )


class EpochManager:
    """
    Manage registration epoch timing.

    This class does NOT implement Phase 1 cryptography.

    Phase 1 remains responsible for:

        PSK authentication
        DID and ECC identity
        challenge response
        proof of possession
        device leaf creation
        Merkle tree construction
        Merkle root generation
        inclusion proof generation
        root anchoring

    EpochManager only decides:

        which epoch a device belongs to
        when registration closes
        when the Phase 1 batch should be finalized
        when the next epoch begins
    """

    def __init__(
        self,
        fog: FogNode,
        clock,
        config: EpochConfiguration | None = None,
    ):

        self.fog = fog
        self.clock = clock

        self.config = (
            config
            if config is not None
            else EpochConfiguration()
        )

        self.epoch_number = 1
        self.epoch_start = clock.now

        # Stores Phase 1 BatchResult objects after finalization.
        self.finalized_epochs: dict[int, object] = {}

        # Devices arriving after cutoff can be held here
        # until the next epoch begins.
        self.next_epoch_queue = []

        print(
            "\n[EPOCH_MANAGER] started"
        )

        self.print_epoch_status()

    # =========================================================
    # TIME INFORMATION
    # =========================================================

    @property
    def elapsed(self) -> int:
        """Return elapsed simulated time in the current epoch."""

        return self.clock.now - self.epoch_start

    @property
    def cutoff_time(self) -> int:
        """Absolute simulated time of registration cutoff."""

        return (
            self.epoch_start
            + self.config.registration_cutoff
        )

    @property
    def finalization_time(self) -> int:
        """Absolute simulated time of epoch finalization."""

        return (
            self.epoch_start
            + self.config.duration
        )

    # =========================================================
    # EPOCH STATE
    # =========================================================

    def registration_open(self) -> bool:
        """
        Return True while devices may still enter
        the current epoch.
        """

        return (
            self.clock.now
            < self.cutoff_time
        )

    def finalization_due(self) -> bool:
        """Return True once the epoch deadline is reached."""

        return (
            self.clock.now
            >= self.finalization_time
        )

    def state(self) -> str:
        """Return current epoch state."""

        if self.finalization_due():
            return "FINALIZATION_DUE"

        if self.registration_open():
            return "REGISTRATION_OPEN"

        return "REGISTRATION_CLOSED"

    # =========================================================
    # PHASE 1 BATCH INFORMATION
    # =========================================================

    def current_batch_id(self) -> str:
        """
        Return the currently open Phase 1 registration batch.

        Phase 1 remains the owner of the actual batch storage.
        """

        row = self.fog.connection.execute(
            """
            SELECT batch_id
            FROM batches
            WHERE status = 'open'
            ORDER BY created_at DESC
            LIMIT 1
            """
        ).fetchone()

        if row is None:
            raise RuntimeError(
                "no open Phase 1 batch exists"
            )

        return row["batch_id"]

    def current_device_count(self) -> int:
        """Return number of devices currently queued."""

        batch_id = self.current_batch_id()

        row = self.fog.connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM open_leaves
            WHERE batch_id = ?
            """,
            (batch_id,),
        ).fetchone()

        return int(row["total"])

    # =========================================================
    # DEVICE ARRIVAL CLASSIFICATION
    # =========================================================

    def classify_arrival(
        self,
        agent,
    ) -> str:
        """
        Decide whether a DeviceAgent may join the current epoch.

        No authentication or registration occurs here.
        """

        if self.registration_open():

            print(
                f"[EPOCH_DECISION] "
                f"epoch={self.epoch_number} "
                f"decision=CURRENT_EPOCH"
            )

            return "CURRENT_EPOCH"

        print(
            f"[EPOCH_DECISION] "
            f"epoch={self.epoch_number} "
            f"decision=NEXT_EPOCH "
            f"reason=registration cutoff passed"
        )

        return "NEXT_EPOCH"

    # =========================================================
    # DEVICE REGISTRATION
    # =========================================================

    def register_agent(
        self,
        agent,
    ):
        """
        Register a DeviceAgent into the current epoch.

        EpochManager performs no cryptographic registration itself.

        The DeviceAgent calls the existing Phase 1 Device.register()
        method, meaning the original Phase 1 implementation is reused.
        """

        decision = self.classify_arrival(
            agent
        )

        if decision == "NEXT_EPOCH":

            self.queue_for_next_epoch(
                agent
            )

            return None

        # Calls the existing Phase 1 workflow.
        registration = agent.register(
            self.fog
        )

        print(
            f"[EPOCH_QUEUE] "
            f"did={agent.did} "
            f"batch={registration.batch_id} "
            f"status=QUEUED"
        )

        return registration

    # =========================================================
    # NEXT EPOCH QUEUE
    # =========================================================

    def queue_for_next_epoch(
        self,
        agent,
    ) -> None:
        """
        Hold a late arriving device until the next epoch begins.

        The device is NOT inserted into the current Phase 1
        registration batch.
        """

        if agent not in self.next_epoch_queue:
            self.next_epoch_queue.append(
                agent
            )

        print(
            f"[NEXT_EPOCH_QUEUE] "
            f"did={agent.did} "
            f"target_epoch={self.epoch_number + 1} "
            f"status=WAITING"
        )

    def release_next_epoch_queue(self) -> list:
        """
        Return devices waiting for the newly opened epoch.

        Simulator is responsible for registering them.
        """

        waiting = list(
            self.next_epoch_queue
        )

        self.next_epoch_queue.clear()

        return waiting


    def remove_revoked_from_open_batch(
        self,
        is_revoked,
    ) -> list[str]:
        """
        Remove devices that were revoked before finalization
        from the current active registration batch.

        Historical finalized epochs are never modified.
        """

        batch_id = self.current_batch_id()

        rows = self.fog.connection.execute(
            """
            SELECT did
            FROM open_leaves
            WHERE batch_id = ?
            """,
            (batch_id,),
        ).fetchall()

        removed = []

        for row in rows:

            did = row["did"]

            if is_revoked(did):

                self.fog.connection.execute(
                    """
                    DELETE FROM open_leaves
                    WHERE batch_id = ?
                    AND did = ?
                    """,
                    (
                        batch_id,
                        did,
                    ),
                )

                removed.append(did)

                print(
                    f"[REVOCATION_FILTER] "
                    f"did={did} "
                    f"batch={batch_id} "
                    f"decision=EXCLUDED"
                )

        if removed:
            self.fog.connection.commit()

        return removed
    # =========================================================
    # FINALIZATION
    # =========================================================

    def finalize_if_due(
            self,
             is_revoked=None,
    ):
        """
        Finalize the current Phase 1 batch once the epoch
        deadline has been reached.

        Merkle tree construction itself is performed entirely
        by Phase 1 FogNode.close_batch().
        """

        if not self.finalization_due():

            print(
                f"[EPOCH] "
                f"epoch={self.epoch_number} "
                f"finalization=NOT_DUE "
                f"current_time={self.clock.now}s "
                f"deadline={self.finalization_time}s"
            )

            return None

        batch_id = self.current_batch_id()
        if is_revoked is not None:
            removed_revoked = (
                self.remove_revoked_from_open_batch(
                    is_revoked
                )
            )

            if removed_revoked:
                print(
                    f"\n[EPOCH_REVOCATION_FILTER] "
                    f"excluded={len(removed_revoked)}"
                )
        count = self.current_device_count()

        if count == 0:

            print(
                f"[EPOCH] "
                f"epoch={self.epoch_number} "
                f"finalization=SKIPPED "
                f"reason=no registered devices"
            )

            return None

        finalized_epoch_number = (
            self.epoch_number
        )

        finalized_at = (
            self.finalization_time
        )

        print(
            "\n"
            "========================================"
        )

        print(
            f"EPOCH "
            f"{finalized_epoch_number} "
            f"FINALIZATION"
        )

        print(
            "========================================"
        )

        print(
            f"Simulated time: "
            f"{self.clock.now}s"
        )

        print(
            f"Closing batch: "
            f"{batch_id}"
        )

        print(
            f"Eligible devices: "
            f"{count}"
        )

        # -----------------------------------------------------
        # CALL PHASE 1
        # -----------------------------------------------------

        result = self.fog.close_batch(
            batch_id
        )

        self.finalized_epochs[
            finalized_epoch_number
        ] = result

        print(
            f"\n[EPOCH_FINALIZED] "
            f"epoch={finalized_epoch_number} "
            f"root={result.root} "
            f"devices={len(result.proofs)}"
        )

        # -----------------------------------------------------
        # MOVE SIMULATION TO NEXT EPOCH
        # -----------------------------------------------------

        self.epoch_number += 1
        self.epoch_start = finalized_at

        print(
            f"\n[EPOCH_START] "
            f"epoch={self.epoch_number} "
            f"start={self.epoch_start}s "
            f"cutoff={self.cutoff_time}s "
            f"finalize={self.finalization_time}s"
        )

        return result

    # =========================================================
    # FINALIZED EPOCH INFORMATION
    # =========================================================

    def get_finalized_epoch(
        self,
        epoch_number: int,
    ):
        """Return a previously finalized Phase 1 batch result."""

        return self.finalized_epochs.get(
            epoch_number
        )

    # =========================================================
    # STATUS DISPLAY
    # =========================================================

    def print_epoch_status(self) -> None:
        """Display current epoch timing and state."""

        print(
            "\n"
            "----------------------------------------"
        )

        print(
            f"Epoch: "
            f"{self.epoch_number}"
        )

        print(
            f"Current simulated time: "
            f"{self.clock.now}s"
        )

        print(
            f"Epoch started: "
            f"{self.epoch_start}s"
        )

        print(
            f"Registration cutoff: "
            f"{self.cutoff_time}s"
        )

        print(
            f"Finalization deadline: "
            f"{self.finalization_time}s"
        )

        print(
            f"State: "
            f"{self.state()}"
        )

        print(
            "----------------------------------------"
        )