"""Deterministic virtual clock for the IIoT simulation."""

from __future__ import annotations


class SimulationClock:
    """
    Virtual clock used by the parent simulation.

    The clock allows the framework to simulate device arrivals,
    registration cutoffs and epoch finalization without waiting
    for real time to pass.

    Example:
        t = 0   -> epoch starts
        t = 3   -> device arrives
        t = 20  -> provisional device arrives
        t = 25  -> registration cutoff
        t = 30  -> epoch finalization
    """

    def __init__(self, start_time: int = 0):
        if start_time < 0:
            raise ValueError(
                "simulation start time cannot be negative"
            )

        self._time = start_time

    @property
    def now(self) -> int:
        """Return the current simulated time."""

        return self._time

    def advance(self, seconds: int) -> int:
        """
        Advance the clock by a number of simulated seconds.
        """

        if seconds < 0:
            raise ValueError(
                "simulation time cannot move backwards"
            )

        self._time += seconds

        self._log_time()

        return self._time

    def advance_to(self, target_time: int) -> int:
        """
        Move directly to a specific simulated time.

        This is useful for processing scheduled events such as
        device arrivals, registration cutoff and finalization.
        """

        if target_time < self._time:
            raise ValueError(
                "simulation time cannot move backwards"
            )

        self._time = target_time

        self._log_time()

        return self._time

    def _log_time(self) -> None:
        """Display the current virtual simulation time."""

        print(
            f"\n[CLOCK] simulated time = "
            f"{self._time}s"
        )