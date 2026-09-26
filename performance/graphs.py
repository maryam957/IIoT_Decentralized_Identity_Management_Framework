"""
Generate performance graphs for the
IIoT Decentralized Identity Management Framework.

The graphs are generated directly from the CSV files
created by performance_test.py.
"""

from __future__ import annotations

import csv
import os

import matplotlib.pyplot as plt


# ============================================================
# PATHS
# ============================================================

RESULTS_DIRECTORY = "performance_results"

SCALABILITY_FILE = os.path.join(
    RESULTS_DIRECTORY,
    "scalability_results.csv",
)

COMPARISON_FILE = os.path.join(
    RESULTS_DIRECTORY,
    "batch_vs_rebuild.csv",
)

GRAPH_DIRECTORY = os.path.join(
    RESULTS_DIRECTORY,
    "graphs",
)


# ============================================================
# LOAD CSV DATA
# ============================================================


def load_scalability_results() -> list[dict]:

    results = []

    with open(
        SCALABILITY_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            results.append(
                {
                    "device_count":
                        int(row["device_count"]),

                    "total_registration_ms":
                        float(
                            row[
                                "total_registration_ms"
                            ]
                        ),

                    "average_registration_ms":
                        float(
                            row[
                                "average_registration_ms"
                            ]
                        ),

                    "batch_finalization_ms":
                        float(
                            row[
                                "batch_finalization_ms"
                            ]
                        ),

                    "average_verification_ms":
                        float(
                            row[
                                "average_verification_ms"
                            ]
                        ),

                    "total_verification_ms":
                        float(
                            row[
                                "total_verification_ms"
                            ]
                        ),

                    "total_processing_ms":
                        float(
                            row[
                                "total_processing_ms"
                            ]
                        ),
                }
            )

    return results


def load_comparison_results() -> list[dict]:

    results = []

    with open(
        COMPARISON_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            results.append(
                {
                    "device_count":
                        int(row["device_count"]),

                    "batch_build_ms":
                        float(
                            row[
                                "batch_build_ms"
                            ]
                        ),

                    "repeated_rebuild_ms":
                        float(
                            row[
                                "repeated_rebuild_ms"
                            ]
                        ),

                    "rebuild_overhead_ratio":
                        float(
                            row[
                                "rebuild_overhead_ratio"
                            ]
                        ),
                }
            )

    return results


# ============================================================
# GRAPH 1
# FRAMEWORK SCALABILITY
# ============================================================


def graph_total_processing(
    results: list[dict],
) -> None:

    devices = [
        row["device_count"]
        for row in results
    ]

    processing = [
        row["total_processing_ms"]
        for row in results
    ]

    plt.figure(
        figsize=(9, 6)
    )

    plt.plot(
        devices,
        processing,
        marker="o",
        linewidth=2,
    )

    plt.title(
        "Framework Scalability"
    )

    plt.xlabel(
        "Number of Devices"
    )

    plt.ylabel(
        "Total Processing Time (ms)"
    )

    plt.grid(
        True,
        alpha=0.3,
    )

    plt.tight_layout()

    path = os.path.join(
        GRAPH_DIRECTORY,
        "framework_scalability.png",
    )

    plt.savefig(
        path,
        dpi=300,
    )

    plt.close()

    print(
        f"[GRAPH] Created: {path}"
    )


# ============================================================
# GRAPH 2
# MERKLE BATCH FINALIZATION
# ============================================================


def graph_batch_finalization(
    results: list[dict],
) -> None:

    devices = [
        row["device_count"]
        for row in results
    ]

    finalization = [
        row["batch_finalization_ms"]
        for row in results
    ]

    plt.figure(
        figsize=(9, 6)
    )

    plt.plot(
        devices,
        finalization,
        marker="o",
        linewidth=2,
    )

    plt.title(
        "Merkle Batch Finalization Performance"
    )

    plt.xlabel(
        "Number of Devices"
    )

    plt.ylabel(
        "Batch Finalization Time (ms)"
    )

    plt.grid(
        True,
        alpha=0.3,
    )

    plt.tight_layout()

    path = os.path.join(
        GRAPH_DIRECTORY,
        "batch_finalization.png",
    )

    plt.savefig(
        path,
        dpi=300,
    )

    plt.close()

    print(
        f"[GRAPH] Created: {path}"
    )


# ============================================================
# GRAPH 3
# BATCH VS REPEATED REBUILD
# ============================================================


def graph_batch_vs_rebuild(
    results: list[dict],
) -> None:

    devices = [
        row["device_count"]
        for row in results
    ]

    batch = [
        row["batch_build_ms"]
        for row in results
    ]

    rebuild = [
        row["repeated_rebuild_ms"]
        for row in results
    ]

    plt.figure(
        figsize=(9, 6)
    )

    plt.plot(
        devices,
        batch,
        marker="o",
        linewidth=2,
        label="Build Once Per Batch",
    )

    plt.plot(
        devices,
        rebuild,
        marker="o",
        linewidth=2,
        label="Rebuild After Every Device",
    )

    plt.title(
        "Batch Construction vs Repeated Merkle Rebuilding"
    )

    plt.xlabel(
        "Number of Devices"
    )

    plt.ylabel(
        "Merkle Construction Time (ms)"
    )

    plt.legend()

    plt.grid(
        True,
        alpha=0.3,
    )

    plt.tight_layout()

    path = os.path.join(
        GRAPH_DIRECTORY,
        "batch_vs_rebuild.png",
    )

    plt.savefig(
        path,
        dpi=300,
    )

    plt.close()

    print(
        f"[GRAPH] Created: {path}"
    )


# ============================================================
# GRAPH 4
# RELATIVE REBUILD OVERHEAD
# ============================================================


def graph_rebuild_overhead(
    results: list[dict],
) -> None:

    devices = [
        row["device_count"]
        for row in results
    ]

    overhead = [
        row["rebuild_overhead_ratio"]
        for row in results
    ]

    plt.figure(
        figsize=(9, 6)
    )

    plt.plot(
        devices,
        overhead,
        marker="o",
        linewidth=2,
    )

    plt.title(
        "Cost of Rebuilding the Merkle Tree After Every Registration"
    )

    plt.xlabel(
        "Number of Devices"
    )

    plt.ylabel(
        "Relative Cost Compared With Batch Construction"
    )

    plt.grid(
        True,
        alpha=0.3,
    )

    plt.tight_layout()

    path = os.path.join(
        GRAPH_DIRECTORY,
        "rebuild_overhead.png",
    )

    plt.savefig(
        path,
        dpi=300,
    )

    plt.close()

    print(
        f"[GRAPH] Created: {path}"
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
        "GENERATING PERFORMANCE GRAPHS"
    )

    print(
        "========================================"
    )

    os.makedirs(
        GRAPH_DIRECTORY,
        exist_ok=True,
    )

    scalability_results = (
        load_scalability_results()
    )

    comparison_results = (
        load_comparison_results()
    )

    graph_total_processing(
        scalability_results
    )

    graph_batch_finalization(
        scalability_results
    )

    graph_batch_vs_rebuild(
        comparison_results
    )

    graph_rebuild_overhead(
        comparison_results
    )

    print(
        "\n"
        "========================================"
    )

    print(
        "GRAPH GENERATION COMPLETE"
    )

    print(
        "========================================"
    )

    print(
        f"\nGraphs saved in: "
        f"{GRAPH_DIRECTORY}"
    )


if __name__ == "__main__":
    main()