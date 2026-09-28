"""Phase 3 performance evaluation."""

import csv
import os
import statistics
import time

from phase1.device import Device
from phase1.fog_node import FogNode
from phase3.authorization import authorize
from phase3.verification import verify_identity
from phase2.token_service import TokenService


DEVICE_COUNTS = [5, 10, 25, 50, 100]
REPEATS = 5

RESULTS_DIRECTORY = "performance_results"

PHASE3_FILE = os.path.join(
    RESULTS_DIRECTORY,
    "phase3_results.csv",
)


def create_devices(fog, count):
    """Register devices into one open batch."""

    devices = []

    registration_times = []

    for _ in range(count):

        device = Device(
            "temperature sensor"
        )

        start = time.perf_counter()

        device.register(
            fog,
            fog.psk,
            metadata={
                "role": "temperature_sensor"
            },
        )

        end = time.perf_counter()

        registration_times.append(
            end - start
        )

        devices.append(device)

    return devices, registration_times


def get_open_batch_id(fog):
    """Return the current open batch ID."""

    row = fog.connection.execute(
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
            "no open registration batch found"
        )

    return row["batch_id"]


def run_single_experiment(device_count):
    """Run one complete Phase 3 performance experiment."""

    fog = FogNode()

    # --------------------------------------------------------
    # REGISTRATION
    # --------------------------------------------------------

    registration_start = time.perf_counter()

    devices, registration_times = create_devices(
        fog,
        device_count,
    )
    
    
    # --------------------------------------------------------
    # TEMPORARY TOKEN VALIDATION
    # --------------------------------------------------------

    token_service = TokenService(
        fog.connection
    )

    token = token_service.issue_token(
        devices[0].did
    )

    token_validation_times = []

    for _ in range(10):

        start = time.perf_counter()

        valid, payload, reason = (
            token_service.verify_token(
                token
            )
        )

        end = time.perf_counter()

        token_validation_times.append(
            end - start
        )

        if not valid:
            raise RuntimeError(
                "temporary token validation failed: "
                + reason
            )

    average_token_validation = (
        statistics.mean(
            token_validation_times
        )
    )
    
    

    registration_end = time.perf_counter()

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
    # BATCH PROCESSING
    # --------------------------------------------------------

    batch_id = get_open_batch_id(
        fog
    )

    batch_start = time.perf_counter()

    batch_result = fog.close_batch(
        batch_id
    )

    batch_end = time.perf_counter()

    batch_time = (
        batch_end
        - batch_start
    )

    # --------------------------------------------------------
    # PROOF GENERATION
    # --------------------------------------------------------

    proof_generation_times = []

    for device in devices:

        start = time.perf_counter()

        fog.get_proof(
            device.did,
            batch_result.epoch_id,
            log=False,
        )

        end = time.perf_counter()

        proof_generation_times.append(
            end - start
        )

    average_proof_generation = (
        statistics.mean(
            proof_generation_times
        )
    )

    # --------------------------------------------------------
    # IDENTITY VERIFICATION
    # --------------------------------------------------------

    verification_times = []

    successful_verifications = 0

    for device in devices:

        start = time.perf_counter()

        valid, reason = verify_identity(
            fog,
            device.did,
            device.public_key_bytes,
            batch_result.epoch_id,
        )

        end = time.perf_counter()

        verification_times.append(
            end - start
        )

        if valid:
            successful_verifications += 1

    average_verification = (
        statistics.mean(
            verification_times
        )
    )

    # --------------------------------------------------------
    # AUTHORIZATION / RESOURCE ACCESS
    # --------------------------------------------------------

    authorization_times = []

    successful_authorizations = 0

    for device in devices:

        start = time.perf_counter()

        allowed, reason = authorize(
            fog,
            device.did,
            device.public_key_bytes,
            batch_result.epoch_id,
            "temperature_data",
            "read",
        )

        end = time.perf_counter()

        authorization_times.append(
            end - start
        )

        if allowed:
            successful_authorizations += 1

    average_authorization = (
        statistics.mean(
            authorization_times
        )
    )

    # --------------------------------------------------------
    # THROUGHPUT
    # --------------------------------------------------------

    verification_total = sum(
        verification_times
    )

    if verification_total > 0:
        verification_throughput = (
            device_count
            / verification_total
        )
    else:
        verification_throughput = 0

    registration_total = (
        total_registration_time
    )

    if registration_total > 0:
        registration_throughput = (
            device_count
            / registration_total
        )
    else:
        registration_throughput = 0

    # --------------------------------------------------------
    # TOTAL PROCESSING
    # --------------------------------------------------------

    total_processing = (
        total_registration_time
        + batch_time
        + sum(proof_generation_times)
        + sum(verification_times)
        + sum(authorization_times)
    )

    result = {
        "device_count": device_count,

        "registration_ms":
            total_registration_time * 1000,

        "average_registration_ms":
            average_registration_time * 1000,

        "batch_processing_ms":
            batch_time * 1000,

        "proof_generation_ms":
            average_proof_generation * 1000,

        "verification_ms":
            average_verification * 1000,

        "token_validation_ms":
            average_token_validation * 1000,

        "resource_access_ms":
            average_authorization * 1000,

        "registration_throughput":
            registration_throughput,

        "verification_throughput":
            verification_throughput,

        "total_processing_ms":
            total_processing * 1000,

        "successful_verifications":
            successful_verifications,

        "successful_authorizations":
            successful_authorizations,
    }

    fog.connection.close()

    return result


def run_repeated_experiment(device_count):
    """Run the same experiment five times and average the results."""

    results = []

    for run_number in range(
        1,
        REPEATS + 1,
    ):

        print(
            "Phase 3 performance: "
            "{} devices, run {}/{}".format(
                device_count,
                run_number,
                REPEATS,
            )
        )

        result = run_single_experiment(
            device_count
        )

        results.append(
            result
        )

    return {
        "device_count": device_count,

        "registration_ms":
            statistics.mean(
                r["registration_ms"]
                for r in results
            ),

        "average_registration_ms":
            statistics.mean(
                r["average_registration_ms"]
                for r in results
            ),

        "batch_processing_ms":
            statistics.mean(
                r["batch_processing_ms"]
                for r in results
            ),

        "proof_generation_ms":
            statistics.mean(
                r["proof_generation_ms"]
                for r in results
            ),

        "verification_ms":
            statistics.mean(
                r["verification_ms"]
                for r in results
            ),

        "token_validation_ms":
            statistics.mean(
                r["token_validation_ms"]
                for r in results
            ),

        "resource_access_ms":
            statistics.mean(
                r["resource_access_ms"]
                for r in results
            ),

        "registration_throughput":
            statistics.mean(
                r["registration_throughput"]
                for r in results
            ),

        "verification_throughput":
            statistics.mean(
                r["verification_throughput"]
                for r in results
            ),

        "total_processing_ms":
            statistics.mean(
                r["total_processing_ms"]
                for r in results
            ),

        "successful_verifications":
            int(
                statistics.mean(
                    r["successful_verifications"]
                    for r in results
                )
            ),

        "successful_authorizations":
            int(
                statistics.mean(
                    r["successful_authorizations"]
                    for r in results
                )
            ),
    }


def save_results(results):
    """Save Phase 3 performance results to CSV."""

    os.makedirs(
        RESULTS_DIRECTORY,
        exist_ok=True,
    )

    fieldnames = [
        "device_count",
        "registration_ms",
        "average_registration_ms",
        "batch_processing_ms",
        "proof_generation_ms",
        "verification_ms",
        "token_validation_ms",
        "resource_access_ms",
        "registration_throughput",
        "verification_throughput",
        "total_processing_ms",
        "successful_verifications",
        "successful_authorizations",
    ]

    with open(
        PHASE3_FILE,
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
        "\nPhase 3 results saved to: {}".format(
            PHASE3_FILE
        )
    )


def print_results(results):
    """Display the averaged performance results."""

    print(
        "\n========================================"
    )

    print(
        "PHASE 3 PERFORMANCE RESULTS"
    )

    print(
        "========================================"
    )

    for result in results:

        print(
            "\nDevices: {}".format(
                result["device_count"]
            )
        )

        print(
            "Registration: {:.4f} ms".format(
                result["registration_ms"]
            )
        )

        print(
            "Batch processing: {:.4f} ms".format(
                result["batch_processing_ms"]
            )
        )

        print(
            "Proof generation: {:.4f} ms".format(
                result["proof_generation_ms"]
            )
        )

        print(
            "Verification: {:.4f} ms".format(
                result["verification_ms"]
            )
        )

        print(
            "Resource access: {:.4f} ms".format(
                result["resource_access_ms"]
            )
        )

        print(
            "Registration throughput: {:.2f} devices/s".format(
                result["registration_throughput"]
            )
        )

        print(
            "Verification throughput: {:.2f} devices/s".format(
                result["verification_throughput"]
            )
        )


def main():

    print(
        "========================================"
    )

    print(
        "IIoT PHASE 3 PERFORMANCE EVALUATION"
    )

    print(
        "========================================"
    )

    print(
        "Device counts: {}".format(
            DEVICE_COUNTS
        )
    )

    print(
        "Runs per count: {}".format(
            REPEATS
        )
    )

    results = []

    for device_count in DEVICE_COUNTS:

        result = run_repeated_experiment(
            device_count
        )

        results.append(
            result
        )

    print_results(
        results
    )

    save_results(
        results
    )


if __name__ == "__main__":
    main()
