#!/usr/bin/env python3
"""
Convert a classic .pcap capture into the log format expected by this project.

Output format per line:
    <src_ip> <dst_port> <count> <attack_type>

Attack type is assigned with lightweight heuristics so the existing C++ menu
can use the generated file without further changes.
"""

from __future__ import annotations

import argparse
import ipaddress
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
ETHERTYPE_IPV4 = 0x0800
PROTO_TCP = 6
PROTO_UDP = 17
LOGIN_PORTS = {21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 3389}


@dataclass
class PacketRecord:
    timestamp: int
    src_ip: str
    dst_port: int
    protocol: int
    tcp_syn: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a classic .pcap file into the project's logs.txt format."
    )
    parser.add_argument("pcap_file", help="Path to the input .pcap file")
    parser.add_argument(
        "-o",
        "--output",
        default="logs.txt",
        help="Path to the generated log file (default: logs.txt)",
    )
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=3,
        help="Unique destination ports from one source IP before tagging as PORT_SCAN",
    )
    parser.add_argument(
        "--failed-login-threshold",
        type=int,
        default=5,
        help="Repeated SYNs to a login-related port before tagging as FAILED_LOGIN",
    )
    return parser.parse_args()


def detect_endian_and_validate(handle) -> str:
    magic = handle.read(4)
    if len(magic) != 4:
        raise ValueError("The input file is empty or incomplete.")
    if magic == PCAPNG_MAGIC:
        raise ValueError(
            "PCAPNG is not supported by this converter yet. Please export the capture as classic .pcap first."
        )

    endian_map = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    endian = endian_map.get(magic)
    if endian is None:
        raise ValueError("Unsupported capture format or invalid PCAP magic number.")

    rest = handle.read(20)
    if len(rest) != 20:
        raise ValueError("The PCAP global header is incomplete.")
    return endian


def read_packet_records(pcap_path: Path) -> list[PacketRecord]:
    records: list[PacketRecord] = []

    with pcap_path.open("rb") as handle:
        endian = detect_endian_and_validate(handle)
        packet_header = struct.Struct(f"{endian}IIII")

        while True:
            header_bytes = handle.read(packet_header.size)
            if not header_bytes:
                break
            if len(header_bytes) != packet_header.size:
                raise ValueError("Encountered a truncated packet header in the PCAP file.")

            ts_sec, _ts_usec, incl_len, _orig_len = packet_header.unpack(header_bytes)
            frame = handle.read(incl_len)
            if len(frame) != incl_len:
                raise ValueError("Encountered a truncated packet payload in the PCAP file.")

            record = parse_ethernet_frame(frame, ts_sec)
            if record is not None:
                records.append(record)

    return records


def parse_ethernet_frame(frame: bytes, timestamp: int) -> PacketRecord | None:
    if len(frame) < 14:
        return None

    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != ETHERTYPE_IPV4:
        return None

    return parse_ipv4_packet(frame[14:], timestamp)


def parse_ipv4_packet(packet: bytes, timestamp: int) -> PacketRecord | None:
    if len(packet) < 20:
        return None

    version_ihl = packet[0]
    version = version_ihl >> 4
    if version != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        return None

    protocol = packet[9]
    src_ip = str(ipaddress.IPv4Address(packet[12:16]))
    payload = packet[ihl:]

    if protocol == PROTO_TCP:
        return parse_tcp_segment(timestamp, src_ip, payload, protocol)
    if protocol == PROTO_UDP:
        return parse_udp_datagram(timestamp, src_ip, payload, protocol)
    return None


def parse_tcp_segment(timestamp: int, src_ip: str, payload: bytes, protocol: int) -> PacketRecord | None:
    if len(payload) < 20:
        return None

    _src_port, dst_port = struct.unpack("!HH", payload[:4])
    offset = (payload[12] >> 4) * 4
    if offset < 20 or len(payload) < offset:
        return None

    flags = payload[13]
    syn_only = bool(flags & 0x02) and not bool(flags & 0x10)

    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_port=dst_port,
        protocol=protocol,
        tcp_syn=syn_only,
    )


def parse_udp_datagram(timestamp: int, src_ip: str, payload: bytes, protocol: int) -> PacketRecord | None:
    if len(payload) < 8:
        return None

    _src_port, dst_port = struct.unpack("!HH", payload[:4])
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_port=dst_port,
        protocol=protocol,
        tcp_syn=False,
    )


def classify_records(
    records: list[PacketRecord],
    port_scan_threshold: int,
    failed_login_threshold: int,
) -> list[tuple[str, int, int, str, int]]:
    counts = Counter((record.src_ip, record.dst_port) for record in records)
    syn_counts = Counter(
        (record.src_ip, record.dst_port)
        for record in records
        if record.protocol == PROTO_TCP and record.tcp_syn
    )
    unique_ports_by_ip: dict[str, set[int]] = defaultdict(set)
    first_seen_timestamp: dict[tuple[str, int], int] = {}

    for record in records:
        unique_ports_by_ip[record.src_ip].add(record.dst_port)
        key = (record.src_ip, record.dst_port)
        if key not in first_seen_timestamp or record.timestamp < first_seen_timestamp[key]:
            first_seen_timestamp[key] = record.timestamp

    classified: list[tuple[str, int, int, str, int]] = []
    for src_ip, dst_port in sorted(counts):
        count = counts[(src_ip, dst_port)]
        unique_port_count = len(unique_ports_by_ip[src_ip])

        if dst_port in LOGIN_PORTS and syn_counts[(src_ip, dst_port)] >= failed_login_threshold:
            attack_type = "FAILED_LOGIN"
        elif unique_port_count >= port_scan_threshold:
            attack_type = "PORT_SCAN"
        else:
            attack_type = "NORMAL"

        classified.append(
            (src_ip, dst_port, count, attack_type, first_seen_timestamp[(src_ip, dst_port)])
        )

    return classified


def write_logs(output_path: Path, rows: list[tuple[str, int, int, str, int]]) -> None:
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for src_ip, dst_port, count, attack_type, timestamp in rows:
            handle.write(f"{src_ip} {dst_port} {count} {attack_type} {timestamp}\n")


def main() -> int:
    args = parse_args()
    pcap_path = Path(args.pcap_file)
    output_path = Path(args.output)

    if not pcap_path.exists():
        print(f"Error: input file not found: {pcap_path}", file=sys.stderr)
        return 1

    try:
        records = read_packet_records(pcap_path)
        rows = classify_records(
            records,
            port_scan_threshold=args.port_scan_threshold,
            failed_login_threshold=args.failed_login_threshold,
        )
        write_logs(output_path, rows)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Converted {len(records)} packets into {len(rows)} log rows.")
    print(f"Output written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
