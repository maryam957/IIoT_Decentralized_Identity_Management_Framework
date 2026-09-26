"""
Performance and scalability evaluation for the
IIoT Decentralized Identity Management Framework.

Experiments:

1. Scalability experiment
   Measures:
   registration time
   batch finalization time
   Merkle proof verification time
   total processing time

2. Batch versus repeated rebuild experiment
   Compares:
   building the Merkle tree once after collecting all leaves
   rebuilding the complete Merkle tree after every new leaf

All measurements use the real Phase 1 implementation.
"""

from __future__ import annotations

import csv
import os
import statistics
import time

from phase1.device import Device
from phase1.fog_node import FogNode
from phase1.merkle import build_tree, verify_proof


# ============================================================
# CONFIGURATION
# ============================================================

DEVICE_COUNTS = [
    10,
    50,
    100,
    250,
    500,
    1000,
]

# Each experiment is repeated to reduce random timing noise.
REPEATS = 5

RESULTS_DIRECTORY = "performance_results"

SCALABILITY_FILE = os.path.join(
    RESULTS_DIRECTORY,
    "scalability_results.csv",
)

COMPARISON_FILE = os.path.join(
    RESULTS_DIRECTORY,
    "batch_vs_rebuild.csv",
)


# ============================================================
# PROOF VERIFICATION HELPER
# ============================================================


def verify_device_proof(
    fog: FogNode,
    device: Device,
    epoch_id: int,
) -> bool:
    """
    Retrieve and verify the permanent Merkle proof
    belonging to one registered device.
    """

    proof_package = fog.get_proof(
        device.did,
        epoch_id,
        log=False,
    )

    root_hex = fog.get_root(
        epoch_id
    )

    return verify_proof(
        bytes.fromhex(
            proof_package.leaf_hash
        ),
        proof_package.proof,
        bytes.fromhex(
            root_hex
        ),
    )


# ============================================================
# EXPERIMENT 1
# SINGLE SCALABILITY RUN
# ============================================================


def run_single_experiment(
    device_count: int,
) -> dict:
    """
    Register a number of devices in one batch,
    finalize the batch and verify every generated proof.

    Returns real timing measurements.
    """

    fog = FogNode()

    devices = []

    registration_times = []

    print(
        f"\nRunning scalability experiment with "
        f"{device_count} devices..."
    )

    # --------------------------------------------------------
    # DEVICE REGISTRATION
    # --------------------------------------------------------

    registration_start = (
        time.perf_counter()
    )

    for _ in range(device_count):

        device = Device(
            "temperature sensor"
        )

        start = time.perf_counter()

        device.register(
            fog,
            fog.psk,
        )

        end = time.perf_counter()

        registration_times.append(
            end - start
        )

        devices.append(
            device
        )

    registration_end = (
        time.perf_counter()
    )

    total_registration_time = (
        registration_end
        - registration_start
    )

    average_registration_time = (
        statistics.mean(
            registration_times
        )
    )

    # --------------------------------------------------------
    # LOCATE OPEN BATCH
    # --------------------------------------------------------

    batch_row = fog.connection.execute(
        """
        SELECT batch_id
        FROM batches
        WHERE status = 'open'
        ORDER BY created_at DESC
        LIMIT 1
        """
    ).fetchone()

    if batch_row is None:

        fog.connection.close()

        raise RuntimeError(
            "no open registration batch found"
        )

    batch_id = batch_row[
        "batch_id"
    ]

    # --------------------------------------------------------
    # BATCH FINALIZATION
    # --------------------------------------------------------

    finalization_start = (
        time.perf_counter()
    )

    batch_result = fog.close_batch(
        batch_id
    )

    finalization_end = (
        time.perf_counter()
    )

    finalization_time = (
        finalization_end
        - finalization_start
    )

    # --------------------------------------------------------
    # MERKLE PROOF VERIFICATION
    # --------------------------------------------------------

    verification_times = []

    successful_verifications = 0

    for device in devices:

        start = time.perf_counter()

        valid = verify_device_proof(
            fog,
            device,
            batch_result.epoch_id,
        )

        end = time.perf_counter()

        verification_times.append(
            end - start
        )

        if valid:
            successful_verifications += 1

    average_verification_time = (
        statistics.mean(
            verification_times
        )
    )

    total_verification_time = sum(
        verification_times
    )

    # --------------------------------------------------------
    # TOTAL PROCESSING TIME
    # --------------------------------------------------------

    total_processing_time = (
        total_registration_time
        + finalization_time
        + total_verification_time
    )

    result = {

        "device_count":
            device_count,

        "total_registration_ms":
            total_registration_time
            * 1000,

        "average_registration_ms":
            average_registration_time
            * 1000,

        "batch_finalization_ms":
            finalization_time
            * 1000,

        "average_verification_ms":
            average_verification_time
            * 1000,

        "total_verification_ms":
            total_verification_time
            * 1000,

        "total_processing_ms":
            total_processing_time
            * 1000,

        "successful_verifications":
            successful_verifications,
    }

    fog.connection.close()

    return result


# ============================================================
# REPEATED SCALABILITY EXPERIMENT
# ============================================================


def run_repeated_experiment(
    device_count: int,
) -> dict:
    """
    Repeat the scalability experiment and return
    average measurements.
    """

    runs = []

    for run_number in range(
        1,
        REPEATS + 1,
    ):

        print(
            f"\nScalability run "
            f"{run_number}/{REPEATS}"
        )

        result = run_single_experiment(
            device_count
        )

        runs.append(
            result
        )

    return {

        "device_count":
            device_count,

        "total_registration_ms":
            statistics.mean(
                run[
                    "total_registration_ms"
                ]
                for run in runs
            ),

        "average_registration_ms":
            statistics.mean(
                run[
                    "average_registration_ms"
                ]
                for run in runs
            ),

        "batch_finalization_ms":
            statistics.mean(
                run[
                    "batch_finalization_ms"
                ]
                for run in runs
            ),

        "average_verification_ms":
            statistics.mean(
                run[
                    "average_verification_ms"
                ]
                for run in runs
            ),

        "total_verification_ms":
            statistics.mean(
                run[
                    "total_verification_ms"
                ]
                for run in runs
            ),

        "total_processing_ms":
            statistics.mean(
                run[
                    "total_processing_ms"
                ]
                for run in runs
            ),

        "successful_verifications":
            int(
                statistics.mean(
                    run[
                        "successful_verifications"
                    ]
                    for run in runs
                )
            ),
    }


# ============================================================
# EXPERIMENT 2
# BATCH VS REPEATED MERKLE REBUILD
# ============================================================


def compare_batch_vs_rebuild(
    device_count: int,
) -> dict:
    """
    Compare two Merkle tree construction strategies.

    Strategy 1:
    Collect all device leaves and construct the tree once.

    Strategy 2:
    Rebuild the complete tree whenever another device
    leaf is added.

    The same real Phase 1 build_tree() implementation
    is used in both strategies.
    """

    fog = FogNode()

    # --------------------------------------------------------
    # GENERATE REAL PHASE 1 LEAVES
    # --------------------------------------------------------

    for _ in range(
        device_count
    ):

        device = Device(
            "temperature sensor"
        )

        device.register(
            fog,
            fog.psk,
        )

    batch_row = fog.connection.execute(
        """
        SELECT batch_id
        FROM batches
        WHERE status = 'open'
        ORDER BY created_at DESC
        LIMIT 1
        """
    ).fetchone()

    if batch_row is None:

        fog.connection.close()

        raise RuntimeError(
            "no open registration batch found"
        )

    batch_id = batch_row[
        "batch_id"
    ]

    rows = fog.connection.execute(
        """
        SELECT leaf_hash
        FROM open_leaves
        WHERE batch_id = ?
        """,
        (
            batch_id,
        ),
    ).fetchall()

    leaves = [
        bytes(
            row["leaf_hash"]
        )
        for row in rows
    ]

    # Phase 1 uses deterministic ordering.
    leaves = sorted(
        leaves
    )

    # --------------------------------------------------------
    # STRATEGY 1
    # BUILD MERKLE TREE ONCE
    # --------------------------------------------------------

    batch_start = (
        time.perf_counter()
    )

    build_tree(
        leaves
    )

    batch_end = (
        time.perf_counter()
    )

    batch_time = (
        batch_end
        - batch_start
    )

    # --------------------------------------------------------
    # STRATEGY 2
    # REBUILD AFTER EVERY NEW DEVICE
    # --------------------------------------------------------

    rebuild_start = (
        time.perf_counter()
    )

    current_leaves = []

    for leaf in leaves:

        current_leaves.append(
            leaf
        )

        build_tree(
            current_leaves
        )

    rebuild_end = (
        time.perf_counter()
    )

    rebuild_time = (
        rebuild_end
        - rebuild_start
    )

    # --------------------------------------------------------
    # RELATIVE COST
    # --------------------------------------------------------

    if batch_time > 0:

        rebuild_overhead_ratio = (
            rebuild_time
            / batch_time
        )

    else:

        rebuild_overhead_ratio = 0

    result = {

        "device_count":
            device_count,

        "batch_build_ms":
            batch_time
            * 1000,

        "repeated_rebuild_ms":
            rebuild_time
            * 1000,

        "rebuild_overhead_ratio":
            rebuild_overhead_ratio,
    }

    fog.connection.close()

    return result


# ============================================================
# REPEATED BATCH VS REBUILD EXPERIMENT
# ============================================================


def run_rebuild_comparison(
    device_count: int,
) -> dict:
    """
    Repeat the batch versus rebuild experiment and
    average the results.
    """

    runs = []

    for run_number in range(
        1,
        REPEATS + 1,
    ):

        print(
            f"\nMerkle comparison "
            f"{device_count} devices "
            f"run {run_number}/{REPEATS}"
        )

        result = (
            compare_batch_vs_rebuild(
                device_count
            )
        )

        runs.append(
            result
        )

    return {

        "device_count":
            device_count,

        "batch_build_ms":
            statistics.mean(
                run[
                    "batch_build_ms"
                ]
                for run in runs
            ),

        "repeated_rebuild_ms":
            statistics.mean(
                run[
                    "repeated_rebuild_ms"
                ]
                for run in runs
            ),

        "rebuild_overhead_ratio":
            statistics.mean(
                run[
                    "rebuild_overhead_ratio"
                ]
                for run in runs
            ),
    }


# ============================================================
# SAVE SCALABILITY RESULTS
# ============================================================


def save_scalability_results(
    results: list[dict],
) -> None:

    os.makedirs(
        RESULTS_DIRECTORY,
        exist_ok=True,
    )

    fieldnames = [
        "device_count",
        "total_registration_ms",
        "average_registration_ms",
        "batch_finalization_ms",
        "average_verification_ms",
        "total_verification_ms",
        "total_processing_ms",
        "successful_verifications",
    ]

    with open(
        SCALABILITY_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(
            results
        )

    print(
        f"\nScalability results saved to: "
        f"{SCALABILITY_FILE}"
    )


# ============================================================
# SAVE COMPARISON RESULTS
# ============================================================


def save_comparison_results(
    results: list[dict],
) -> None:

    os.makedirs(
        RESULTS_DIRECTORY,
        exist_ok=True,
    )

    fieldnames = [
        "device_count",
        "batch_build_ms",
        "repeated_rebuild_ms",
        "rebuild_overhead_ratio",
    ]

    with open(
        COMPARISON_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(
            results
        )

    print(
        f"\nComparison results saved to: "
        f"{COMPARISON_FILE}"
    )


# ============================================================
# DISPLAY SCALABILITY RESULTS
# ============================================================


def print_scalability_results(
    results: list[dict],
) -> None:

    print(
        "\n"
        "========================================"
    )

    print(
        "SCALABILITY RESULTS"
    )

    print(
        "========================================"
    )

    for result in results:

        print(
            f"\nDevices: "
            f"{result['device_count']}"
        )

        print(
            "Average registration: "
            f"{result['average_registration_ms']:.4f} ms"
        )

        print(
            "Total registration: "
            f"{result['total_registration_ms']:.4f} ms"
        )

        print(
            "Batch finalization: "
            f"{result['batch_finalization_ms']:.4f} ms"
        )

        print(
            "Average proof verification: "
            f"{result['average_verification_ms']:.4f} ms"
        )

        print(
            "Total proof verification: "
            f"{result['total_verification_ms']:.4f} ms"
        )

        print(
            "Total processing: "
            f"{result['total_processing_ms']:.4f} ms"
        )

        print(
            "Successful proofs: "
            f"{result['successful_verifications']}"
            f"/{result['device_count']}"
        )


# ============================================================
# DISPLAY BATCH VS REBUILD RESULTS
# ============================================================


def print_comparison_results(
    results: list[dict],
) -> None:

    print(
        "\n"
        "========================================"
    )

    print(
        "BATCH VS REPEATED TREE REBUILD"
    )

    print(
        "========================================"
    )

    for result in results:

        print(
            f"\nDevices: "
            f"{result['device_count']}"
        )

        print(
            "Build tree once: "
            f"{result['batch_build_ms']:.4f} ms"
        )

        print(
            "Repeated rebuild: "
            f"{result['repeated_rebuild_ms']:.4f} ms"
        )

        print(
            "Relative rebuild cost: "
            f"{result['rebuild_overhead_ratio']:.2f}x"
        )


# ============================================================
# MAIN
# ============================================================


def main() -> None:

    print(
        "\n"
        "========================================"
    )

    print(
        "IIoT PERFORMANCE EVALUATION"
    )

    print(
        "========================================"
    )

    print(
        f"\nDevice counts: "
        f"{DEVICE_COUNTS}"
    )

    print(
        f"Runs per experiment: "
        f"{REPEATS}"
    )

    # ========================================================
    # EXPERIMENT 1
    # ========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "EXPERIMENT 1: SCALABILITY"
    )

    print(
        "========================================"
    )

    scalability_results = []

    for device_count in (
        DEVICE_COUNTS
    ):

        result = (
            run_repeated_experiment(
                device_count
            )
        )

        scalability_results.append(
            result
        )

    print_scalability_results(
        scalability_results
    )

    save_scalability_results(
        scalability_results
    )

    # ========================================================
    # EXPERIMENT 2
    # ========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "EXPERIMENT 2: BATCH VS REBUILD"
    )

    print(
        "========================================"
    )

    comparison_results = []

    for device_count in (
        DEVICE_COUNTS
    ):

        result = (
            run_rebuild_comparison(
                device_count
            )
        )

        comparison_results.append(
            result
        )

    print_comparison_results(
        comparison_results
    )

    save_comparison_results(
        comparison_results
    )

    # ========================================================
    # COMPLETE
    # ========================================================

    print(
        "\n"
        "========================================"
    )

    print(
        "PERFORMANCE EVALUATION COMPLETE"
    )

    print(
        "========================================"
    )

    print(
        "\nGenerated:"
    )

    print(
        f"1. {SCALABILITY_FILE}"
    )

    print(
        f"2. {COMPARISON_FILE}"
    )


if __name__ == "__main__":
    main()