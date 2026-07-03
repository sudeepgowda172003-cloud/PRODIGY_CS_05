"""
Task-05: Network Packet Analyzer
Prodigy Infotech Internship

⚠️  ETHICAL USE ONLY:
    - Run ONLY on your OWN network
    - ONLY for learning/testing purposes
    - NEVER sniff traffic without authorization
    - Unauthorized packet sniffing is ILLEGAL

Features:
  - Captures live network packets
  - Displays Source & Destination IP
  - Identifies Protocol (TCP / UDP / ICMP / Other)
  - Shows port numbers
  - Displays payload data (first 100 bytes)
  - Saves log to a file
  - Stop with Ctrl+C
"""

import socket
import struct
import textwrap
import os
import sys
from datetime import datetime


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

LOG_FILE = "packet_log.txt"
PAYLOAD_PREVIEW = 100   # bytes to show from payload


# ──────────────────────────────────────────────
# Packet parsing helpers
# ──────────────────────────────────────────────

def parse_ethernet(data: bytes):
    """Parse Ethernet frame header (14 bytes)."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return (
        format_mac(dest_mac),
        format_mac(src_mac),
        socket.htons(proto),
        data[14:]
    )


def format_mac(mac_bytes: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def parse_ipv4(data: bytes):
    """Parse IPv4 packet header."""
    version_ihl = data[0]
    ihl = (version_ihl & 0xF) * 4   # header length in bytes
    ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return (
        socket.inet_ntoa(src),
        socket.inet_ntoa(dst),
        proto,
        ttl,
        data[ihl:]
    )


def parse_tcp(data: bytes):
    """Parse TCP segment header."""
    src_port, dst_port, seq, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_flags >> 12) * 4
    flags = {
        'URG': (offset_flags & 32) >> 5,
        'ACK': (offset_flags & 16) >> 4,
        'PSH': (offset_flags & 8) >> 3,
        'RST': (offset_flags & 4) >> 2,
        'SYN': (offset_flags & 2) >> 1,
        'FIN': offset_flags & 1
    }
    active_flags = [k for k, v in flags.items() if v]
    return src_port, dst_port, seq, ack, active_flags, data[offset:]


def parse_udp(data: bytes):
    """Parse UDP segment header."""
    src_port, dst_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dst_port, length, data[8:]


def parse_icmp(data: bytes):
    """Parse ICMP packet."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    type_names = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Dest Unreachable',
                  11: 'Time Exceeded', 5: 'Redirect'}
    type_str = type_names.get(icmp_type, f'Type {icmp_type}')
    return type_str, code, checksum, data[4:]


def format_payload(data: bytes, limit: int = PAYLOAD_PREVIEW) -> str:
    """Format raw payload as hex + ASCII."""
    data = data[:limit]
    if not data:
        return "  (no payload)"
    hex_part = ' '.join(f'{b:02x}' for b in data)
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
    lines = textwrap.wrap(hex_part, 48)
    result = []
    for i, line in enumerate(lines):
        ascii_chunk = ascii_part[i * 16:(i + 1) * 16]
        result.append(f"  {line:<48}  {ascii_chunk}")
    return '\n'.join(result)


PROTO_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


# ──────────────────────────────────────────────
# Logger
# ──────────────────────────────────────────────

class PacketLogger:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.packet_count = 0
        self.session_start = datetime.now()
        self._write_header()

    def _write_header(self):
        with open(self.log_file, 'a') as f:
            f.write("\n" + "=" * 60 + "\n")
            f.write(f"  Packet Sniffer Session\n")
            f.write(f"  Started: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")

    def log(self, text: str):
        with open(self.log_file, 'a') as f:
            f.write(text + "\n")

    def write_footer(self):
        duration = datetime.now() - self.session_start
        with open(self.log_file, 'a') as f:
            f.write("\n" + "=" * 60 + "\n")
            f.write(f"  Session Ended\n")
            f.write(f"  Total Packets : {self.packet_count}\n")
            f.write(f"  Duration      : {str(duration).split('.')[0]}\n")
            f.write("=" * 60 + "\n")


# ──────────────────────────────────────────────
# Sniffer
# ──────────────────────────────────────────────

def sniff(packet_count_limit: int, logger: PacketLogger, show_payload: bool):
    """
    Create a raw socket and capture packets.
    Requires root/admin privileges.
    """
    # On Linux use ETH_P_ALL; on Windows use IPPROTO_IP
    if sys.platform == 'win32':
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((socket.gethostbyname(socket.gethostname()), 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print(f"\n  🟢 Sniffing started... (Ctrl+C to stop)\n")
    print(f"  {'#':<5} {'Time':<10} {'Proto':<6} {'Source':<22} {'Destination':<22} {'Info'}")
    print("  " + "─" * 85)

    try:
        while True:
            raw_data, _ = conn.recvfrom(65535)
            logger.packet_count += 1
            ts = datetime.now().strftime('%H:%M:%S')

            # ── Ethernet (Linux) ──
            if sys.platform != 'win32':
                dest_mac, src_mac, eth_proto, ip_data = parse_ethernet(raw_data)
                if eth_proto != 8:   # Only handle IPv4 (0x0800)
                    continue
            else:
                ip_data = raw_data

            # ── IPv4 ──
            try:
                src_ip, dst_ip, proto, ttl, transport_data = parse_ipv4(ip_data)
            except Exception:
                continue

            proto_name = PROTO_NAMES.get(proto, f'OTHER({proto})')
            info = ""
            detail_lines = []

            # ── TCP ──
            if proto == 6:
                try:
                    sp, dp, seq, ack, flags, payload = parse_tcp(transport_data)
                    info = f"{sp} → {dp}  [{','.join(flags)}]"
                    detail_lines = [
                        f"    Src Port : {sp}   Dst Port : {dp}",
                        f"    Seq      : {seq}   Ack: {ack}",
                        f"    Flags    : {', '.join(flags) if flags else 'None'}",
                        f"    TTL      : {ttl}",
                    ]
                    if show_payload and payload:
                        detail_lines.append(f"    Payload ({min(len(payload), PAYLOAD_PREVIEW)} bytes):")
                        detail_lines.append(format_payload(payload))
                except Exception:
                    pass

            # ── UDP ──
            elif proto == 17:
                try:
                    sp, dp, length, payload = parse_udp(transport_data)
                    info = f"{sp} → {dp}  len={length}"
                    detail_lines = [
                        f"    Src Port : {sp}   Dst Port : {dp}",
                        f"    Length   : {length}   TTL: {ttl}",
                    ]
                    if show_payload and payload:
                        detail_lines.append(f"    Payload ({min(len(payload), PAYLOAD_PREVIEW)} bytes):")
                        detail_lines.append(format_payload(payload))
                except Exception:
                    pass

            # ── ICMP ──
            elif proto == 1:
                try:
                    icmp_type, code, chk, payload = parse_icmp(transport_data)
                    info = f"{icmp_type}  code={code}"
                    detail_lines = [
                        f"    Type     : {icmp_type}   Code: {code}",
                        f"    Checksum : {chk}   TTL: {ttl}",
                    ]
                except Exception:
                    pass

            # ── Summary line ──
            summary = f"  {logger.packet_count:<5} {ts:<10} {proto_name:<6} {src_ip:<22} {dst_ip:<22} {info}"
            print(summary)
            logger.log(summary)

            # ── Detail lines ──
            for line in detail_lines:
                print(line)
                logger.log(line)

            if detail_lines:
                print()

            # Stop after limit
            if packet_count_limit and logger.packet_count >= packet_count_limit:
                print(f"\n  ✅ Captured {packet_count_limit} packets. Done.")
                break

    except KeyboardInterrupt:
        print("\n\n  🔴 Stopped by user (Ctrl+C).")
    finally:
        if sys.platform == 'win32':
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        conn.close()
        logger.write_footer()


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def print_banner():
    print("=" * 60)
    print("   🌐 Network Packet Analyzer — Task 05")
    print("   Prodigy Infotech Internship")
    print("=" * 60)
    print("""
  ⚠️  ETHICAL NOTICE:
  Capture packets ONLY on your OWN network.
  Unauthorized sniffing is ILLEGAL.
""")


def main():
    print_banner()

    # Check for root/admin
    if os.name != 'nt' and os.geteuid() != 0:
        print("  ❌ ERROR: Run with sudo/root privileges!")
        print("     sudo python packet_sniffer.py")
        sys.exit(1)

    print("  Options:")
    print("  1. Start Sniffing")
    print("  2. View Log File")
    print("  3. Clear Log File")
    print("  4. Exit")

    while True:
        choice = input("\n  Enter choice (1/2/3/4): ").strip()

        if choice == '1':
            try:
                limit = int(input("  Capture how many packets? (0 = unlimited): "))
            except ValueError:
                limit = 0

            payload_input = input("  Show payload data? (y/n): ").strip().lower()
            show_payload = payload_input == 'y'

            logger = PacketLogger(LOG_FILE)
            sniff(limit, logger, show_payload)

            print(f"\n  📊 Total packets captured : {logger.packet_count}")
            print(f"  📄 Log saved to           : {os.path.abspath(LOG_FILE)}")

        elif choice == '2':
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    print(f.read())
            else:
                print("  ⚠  No log file found.")

        elif choice == '3':
            if os.path.exists(LOG_FILE):
                os.remove(LOG_FILE)
                print("  ✅ Log cleared.")
            else:
                print("  ⚠  No log file to clear.")

        elif choice == '4':
            print("\n  Goodbye! 👋")
            break

        else:
            print("  ⚠  Invalid choice.")


if __name__ == "__main__":
    main()
