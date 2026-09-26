import csv
import os
import statistics
import time

from phase1.device import Device
from phase1.fog_node import FogNode


DEVICE_COUNTS = [5, 10, 25, 50, 100]
REPEATS = 5

RESULTS_DIRECTORY = "performance_results"
RESULTS_FILE = os.path.join(
    RESULTS_DIRECTORY,
    "batch_vs_individual.csv",
)

PSK = "test-psk"


def run_batch(device_count):
    fog = FogNode(PSK)

    start = time.perf_counter()

    batch_id = None

    for _ in range(device_count):
        device = Device()

        registration = device.register(
            fog,
            PSK,
            metadata={"role": "temperature_sensor"},
        )

        batch_id = registration.batch_id

    fog.close_batch(batch_id)

    end = time.perf_counter()

    return end - start


def run_individual(device_count):
    fog = FogNode(PSK)

    start = time.perf_counter()

    for _ in range(device_count):
        device = Device()

        registration = device.register(
            fog,
            PSK,
            metadata={"role": "temperature_sensor"},
        )

        fog.close_batch(
            registration.batch_id
        )

    end = time.perf_counter()

    return end - start


def run_experiment():
    results = []

    print()
    print("Starting batch vs individual performance experiment")
    print("Device counts:", DEVICE_COUNTS)
    print("Repetitions:", REPEATS)
    print()

    for device_count in DEVICE_COUNTS:

        batch_times = []
        individual_times = []

        print("----------------------------------------")
        print("Testing devices:", device_count)
        print("----------------------------------------")

        for repeat in range(REPEATS):

            print("Run:", repeat + 1, "of", REPEATS)

            batch_time = run_batch(
                device_count
            )

            individual_time = run_individual(
                device_count
            )

            batch_times.append(batch_time)
            individual_times.append(individual_time)

            print(
                "  Batch time:",
                round(batch_time * 1000, 4),
                "ms"
            )

            print(
                "  Individual time:",
                round(individual_time * 1000, 4),
                "ms"
            )

        average_batch = statistics.mean(
            batch_times
        )

        average_individual = statistics.mean(
            individual_times
        )

        speedup = (
            average_individual / average_batch
            if average_batch > 0
            else 0
        )

        results.append(
            {
                "device_count": device_count,
                "batch_time_ms": average_batch * 1000,
                "individual_time_ms":
                    average_individual * 1000,
                "speedup": speedup,
            }
        )

        print()
        print(
            "Average batch time:",
            round(average_batch * 1000, 4),
            "ms"
        )

        print(
            "Average individual time:",
            round(average_individual * 1000, 4),
            "ms"
        )

        print(
            "Speedup:",
            round(speedup, 2),
            "x"
        )

        print()

    return results


def save_results(results):

    os.makedirs(
        RESULTS_DIRECTORY,
        exist_ok=True,
    )

    with open(
        RESULTS_FILE,
        "w",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "device_count",
                "batch_time_ms",
                "individual_time_ms",
                "speedup",
            ],
        )

        writer.writeheader()
        writer.writerows(results)


def print_results(results):

    print()
    print("=" * 65)
    print("BATCH VS INDIVIDUAL PERFORMANCE RESULTS")
    print("=" * 65)
    print()

    for result in results:

        print(
            "Devices:",
            result["device_count"]
        )

        print(
            "Batch processing:",
            round(
                result["batch_time_ms"],
                4
            ),
            "ms"
        )

        print(
            "Individual processing:",
            round(
                result["individual_time_ms"],
                4
            ),
            "ms"
        )

        print(
            "Speedup:",
            round(
                result["speedup"],
                2
            ),
            "x"
        )

        print("----------------------------------------")

    print()
    print(
        "Results saved to:",
        RESULTS_FILE
    )


def main():

    results = run_experiment()

    save_results(results)

    print_results(results)


if __name__ == "__main__":
    main()
