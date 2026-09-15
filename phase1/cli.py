"""Thin demonstration CLI for the Phase 1 public operations."""

from __future__ import annotations

import argparse

from .device import Device
from .fog_node import DEFAULT_PSK, FogNode


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 1 IIoT identity demo")
    parser.add_argument("command", choices=("register", "close-batch"))
    parser.add_argument("--db", default="phase1.db", help="SQLite database path")
    parser.add_argument("--psk", default=DEFAULT_PSK)
    parser.add_argument("--device-type", default="temperature sensor")
    parser.add_argument("--batch-id")
    args = parser.parse_args()
    fog = FogNode(psk=args.psk, db_path=args.db)
    if args.command == "register":
        result = Device(args.device_type).register(fog, args.psk)
        print(result)
    else:
        batch_id = args.batch_id or fog.connection.execute(
            "SELECT batch_id FROM batches WHERE status = 'open' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()["batch_id"]
        print(fog.close_batch(batch_id))


if __name__ == "__main__":
    main()