#!/usr/bin/env python3
"""Write the deterministic riftpacket seed corpus. Bytes are the demo protocol, not secrets."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "corpus" / "seeds" / "riftpacket"

SEEDS = {
    "00_magic.bin": b"VR",
    "01_open.bin": b"VRO",
    "02_auth.bin": b"VROA" + bytes([1, 2, 3, 4]),
    "03_happy.bin": b"VROA" + bytes([1, 2, 3, 4]) + b"D\x00C",
    "04_length.bin": b"VRL\x00\x04ABCD",
    "05_note.bin": b"VRN\x00",
    "06_scale.bin": b"VRS" + (2).to_bytes(4, "big") + (3).to_bytes(4, "big"),
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in SEEDS.items():
        path = OUT / name
        path.write_bytes(data)
        print(f"{name} {len(data)} {data.hex()}")


if __name__ == "__main__":
    main()
