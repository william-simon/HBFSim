#!/usr/bin/env python3
"""A single read must pay the NVDDR2 channel transfer, not only command and sense time.

nominal.json: 16 KiB page over an 8-bit channel at 1600 MT/s. One read costs the
290 ns read command, 10,000 ns sense plus 20 ns ready, and 8,192 two-byte DDR
transfers at 1.25 ns = 10,240 ns of data-out. Before MQSim patch 0005 the
transfer time truncated to 0 ns and this read took 10,310 ns.
"""

import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
BINARY = (
    pathlib.Path(sys.argv[1])
    if len(sys.argv) > 1
    else ROOT / "build" / "hbf_mqsim_bench"
)
EXPECTED_NS = 290 + 10_000 + 20 + 10_240


def main() -> int:
    completed = subprocess.run(
        [
            str(BINARY),
            "--profile",
            "configs/profiles/nominal.json",
            "--requests",
            "1",
            "--bytes",
            "16384",
            "--operation",
            "read",
            "--arrival-gap-ns",
            "0",
        ],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    result = json.loads(completed.stdout)
    modeled = result["timing_ns"]["modeled"]
    if modeled != EXPECTED_NS:
        print(f"single 16 KiB read modeled {modeled} ns, expected {EXPECTED_NS} ns")
        return 1
    if result["latency_ns"]["p50"] != EXPECTED_NS:
        print(f"single 16 KiB read latency {result['latency_ns']['p50']} ns, expected {EXPECTED_NS} ns")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
