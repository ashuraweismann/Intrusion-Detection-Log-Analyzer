#!/usr/bin/env python3
"""
Generate classic .pcap files for IDS demo purposes.

The default output contains traffic that guarantees all three log categories
produced by the current converter:
    - FAILED_LOGIN
    - PORT_SCAN
    - NORMAL
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


ETHERTYPE_IPV4 = 0x0800
IP_VERSION_IHL = 0x45
IP_TTL = 64
PROTO_TCP = 6
PROTO_UDP = 17
TCP_FLAG_SYN = 0x02
PCAP_MAGIC_LITTLE_ENDIAN = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a demo .pcap for the IDS project."
    )
    parser.add_argument(
        "-o",
        "--output",
        default="demo_all_cases.pcap",
        help="Output .pcap path (default: demo_all_cases.pcap)",
    )
    parser.add_argument(
        "--profile",
        choices=("all-cases", "failed-login-only"),
        default="all-cases",
        help="Choose whether to generate all converter cases or only FAILED_LOGIN traffic",
    )
    parser.add_argument(
        "--failed-login-attempts",
        type=int,
        default=20,
        help="Number of SYN packets used for the FAILED_LOGIN scenario",
    )
    return parser.parse_args()


def ipv4_bytes(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def build_ipv4_header(src_ip: str, dst_ip: str, protocol: int, payload_length: int) -> bytes:
    total_length = 20 + payload_length
    return struct.pack(
        "!BBHHHBBH4s4s",
        IP_VERSION_IHL,
        0,
        total_length,
        0,
        0,
        IP_TTL,
        protocol,
        0,
        ipv4_bytes(src_ip),
        ipv4_bytes(dst_ip),
    )


def wrap_ethernet(ip_payload: bytes) -> bytes:
    ethernet_header = b"\x00" * 12 + struct.pack("!H", ETHERTYPE_IPV4)
    return ethernet_header + ip_payload


def build_tcp_syn_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        0,
        0,
        5 << 4,
        TCP_FLAG_SYN,
        1024,
        0,
        0,
    )
    ip_header = build_ipv4_header(src_ip, dst_ip, PROTO_TCP, len(tcp_header))
    return wrap_ethernet(ip_header + tcp_header)


def build_udp_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    udp_header = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        8,
        0,
    )
    ip_header = build_ipv4_header(src_ip, dst_ip, PROTO_UDP, len(udp_header))
    return wrap_ethernet(ip_header + udp_header)


def build_pcap(packet_frames: list[tuple[int, bytes]]) -> bytes:
    payload = bytearray()
    payload += struct.pack(
        "<IHHIIII",
        PCAP_MAGIC_LITTLE_ENDIAN,
        2,
        4,
        0,
        0,
        65535,
        LINKTYPE_ETHERNET,
    )

    for ts_sec, frame in packet_frames:
        payload += struct.pack("<IIII", ts_sec, 0, len(frame), len(frame))
        payload += frame

    return bytes(payload)


def generate_failed_login_only(attempts: int) -> tuple[list[tuple[int, bytes]], list[str]]:
    src_ip = "192.168.1.50"
    dst_ip = "192.168.1.10"
    dst_port = 22
    frames = []
    base_time = 1714464000

    for attempt_index in range(attempts):
        frames.append(
            (
                base_time + attempt_index,
                build_tcp_syn_frame(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=40000 + attempt_index,
                    dst_port=dst_port,
                ),
            )
        )

    summary = [
        f"FAILED_LOGIN demo: {attempts} TCP SYN packets from {src_ip} to {dst_ip}:{dst_port}",
    ]
    return frames, summary


def generate_all_cases(attempts: int) -> tuple[list[tuple[int, bytes]], list[str]]:
    frames: list[tuple[int, bytes]] = []
    summary: list[str] = []
    first_window = 1714464000
    second_window = 1714467600

    failed_login_src = "192.168.1.50"
    failed_login_dst = "192.168.1.10"
    for attempt_index in range(attempts):
        frames.append(
            (
                first_window + attempt_index,
                build_tcp_syn_frame(
                    src_ip=failed_login_src,
                    dst_ip=failed_login_dst,
                    src_port=40000 + attempt_index,
                    dst_port=22,
                ),
            )
        )
    summary.append(
        f"FAILED_LOGIN scenario: {attempts} TCP SYN packets from {failed_login_src} to {failed_login_dst}:22"
    )

    port_scan_src = "10.10.10.20"
    port_scan_dst = "10.10.10.1"
    scan_ports = (80, 443, 3306, 8080)
    repeats_per_port = 5
    for repeat_index in range(repeats_per_port):
        for port_offset, dst_port in enumerate(scan_ports, start=1):
            frames.append(
                (
                    first_window + 100 + (repeat_index * len(scan_ports)) + port_offset,
                    build_tcp_syn_frame(
                        src_ip=port_scan_src,
                        dst_ip=port_scan_dst,
                        src_port=45000 + (repeat_index * len(scan_ports)) + port_offset,
                        dst_port=dst_port,
                    ),
                )
            )
    summary.append(
        f"PORT_SCAN scenario: {repeats_per_port * len(scan_ports)} TCP SYN packets from {port_scan_src} to {port_scan_dst} across ports 80, 443, 3306, 8080"
    )

    normal_src = "172.16.0.30"
    normal_dst = "172.16.0.1"
    normal_packet_count = 10
    for packet_index in range(normal_packet_count):
        frames.append(
            (
                first_window + 200 + packet_index,
                build_udp_frame(
                    src_ip=normal_src,
                    dst_ip=normal_dst,
                    src_port=53000 + packet_index,
                    dst_port=53,
                ),
            )
        )
    summary.append(
        f"NORMAL scenario: {normal_packet_count} UDP packets from {normal_src} to {normal_dst}:53"
    )

    second_failed_login_src = "192.168.1.60"
    second_failed_login_dst = "192.168.1.20"
    for attempt_index in range(attempts):
        frames.append(
            (
                second_window + attempt_index,
                build_tcp_syn_frame(
                    src_ip=second_failed_login_src,
                    dst_ip=second_failed_login_dst,
                    src_port=50000 + attempt_index,
                    dst_port=23,
                ),
            )
        )
    summary.append(
        f"FAILED_LOGIN scenario 2: {attempts} TCP SYN packets from {second_failed_login_src} to {second_failed_login_dst}:23"
    )

    second_port_scan_src = "10.20.10.20"
    second_port_scan_dst = "10.20.10.1"
    second_scan_ports = (81, 444, 3307, 8081)
    for repeat_index in range(repeats_per_port):
        for port_offset, dst_port in enumerate(second_scan_ports, start=1):
            frames.append(
                (
                    second_window + 100 + (repeat_index * len(second_scan_ports)) + port_offset,
                    build_tcp_syn_frame(
                        src_ip=second_port_scan_src,
                        dst_ip=second_port_scan_dst,
                        src_port=55000 + (repeat_index * len(second_scan_ports)) + port_offset,
                        dst_port=dst_port,
                    ),
                )
            )
    summary.append(
        f"PORT_SCAN scenario 2: {repeats_per_port * len(second_scan_ports)} TCP SYN packets from {second_port_scan_src} to {second_port_scan_dst} across ports 81, 444, 3307, 8081"
    )

    second_normal_src = "172.16.1.30"
    second_normal_dst = "172.16.1.1"
    for packet_index in range(normal_packet_count):
        frames.append(
            (
                second_window + 200 + packet_index,
                build_udp_frame(
                    src_ip=second_normal_src,
                    dst_ip=second_normal_dst,
                    src_port=54000 + packet_index,
                    dst_port=5353,
                ),
            )
        )
    summary.append(
        f"NORMAL scenario 2: {normal_packet_count} UDP packets from {second_normal_src} to {second_normal_dst}:5353"
    )

    return frames, summary


def main() -> int:
    args = parse_args()

    if args.profile == "failed-login-only":
        frames, summary = generate_failed_login_only(args.failed_login_attempts)
    else:
        frames, summary = generate_all_cases(args.failed_login_attempts)

    output_path = Path(args.output)
    output_path.write_bytes(build_pcap(frames))

    print(f"Created demo PCAP: {output_path}")
    for line in summary:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
