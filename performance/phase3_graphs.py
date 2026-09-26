import csv
import os

import matplotlib.pyplot as plt


RESULTS_FILE = "performance_results/phase3_results.csv"
OUTPUT_DIRECTORY = "performance_results/graphs"


def load_results():
    device_counts = []
    registration_times = []
    verification_latencies = []
    verification_throughputs = []

    with open(RESULTS_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            device_counts.append(int(row["device_count"]))
            registration_times.append(float(row["registration_ms"]))
            verification_latencies.append(float(row["verification_ms"]))
            verification_throughputs.append(
                float(row["verification_throughput"])
            )

    return (
        device_counts,
        registration_times,
        verification_latencies,
        verification_throughputs,
    )


def create_registration_graph(
    device_counts,
    registration_times,
):
    plt.figure(figsize=(8, 5))

    plt.plot(
        device_counts,
        registration_times,
        marker="o",
    )

    plt.xlabel("Number of Devices")
    plt.ylabel("Total Registration Time (ms)")
    plt.title("Devices vs Total Registration Time")
    plt.grid(True)

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_DIRECTORY,
            "phase3_registration_time.png",
        ),
        dpi=300,
    )

    plt.close()


def create_verification_graph(
    device_counts,
    verification_latencies,
):
    plt.figure(figsize=(8, 5))

    plt.plot(
        device_counts,
        verification_latencies,
        marker="o",
    )

    plt.xlabel("Number of Devices")
    plt.ylabel("Verification Latency (ms)")
    plt.title("Devices vs Identity Verification Latency")
    plt.grid(True)

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_DIRECTORY,
            "phase3_verification_latency.png",
        ),
        dpi=300,
    )

    plt.close()


def create_throughput_graph(
    device_counts,
    verification_throughputs,
):
    plt.figure(figsize=(8, 5))

    plt.plot(
        device_counts,
        verification_throughputs,
        marker="o",
    )

    plt.xlabel("Number of Devices")
    plt.ylabel("Verification Throughput (devices/s)")
    plt.title("Devices vs Verification Throughput")
    plt.grid(True)

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_DIRECTORY,
            "phase3_throughput.png",
        ),
        dpi=300,
    )

    plt.close()
    

def create_batch_vs_individual_graph():
    device_counts = []
    batch_times = []
    individual_times = []

    with open(
        "performance_results/batch_vs_individual.csv",
        "r",
        newline="",
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:
            device_counts.append(
                int(row["device_count"])
            )

            batch_times.append(
                float(row["batch_time_ms"])
            )

            individual_times.append(
                float(row["individual_time_ms"])
            )

    plt.figure(figsize=(8, 5))

    plt.plot(
        device_counts,
        batch_times,
        marker="o",
        label="Batch processing",
    )

    plt.plot(
        device_counts,
        individual_times,
        marker="o",
        label="Individual processing",
    )

    plt.xlabel("Number of Devices")
    plt.ylabel("Processing Time (ms)")
    plt.title("Batch vs Individual Registration Processing")
    plt.legend()
    plt.grid(True)

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            OUTPUT_DIRECTORY,
            "batch_vs_individual.png",
        ),
        dpi=300,
    )

    plt.close()



def main():
    (
        device_counts,
        registration_times,
        verification_latencies,
        verification_throughputs,
    ) = load_results()

    os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)

    create_registration_graph(
        device_counts,
        registration_times,
    )

    create_verification_graph(
        device_counts,
        verification_latencies,
    )

    create_throughput_graph(
        device_counts,
        verification_throughputs,
    )
    
    create_batch_vs_individual_graph()

    print("Phase 4 graphs generated successfully.")
    print()
    print("Generated files:")
    print(" - performance_results/graphs/phase3_registration_time.png")
    print(" - performance_results/graphs/phase3_verification_latency.png")
    print(" - performance_results/graphs/phase3_throughput.png")
    print(" - performance_results/graphs/batch_vs_individual.png")


if __name__ == "__main__":
    main()
