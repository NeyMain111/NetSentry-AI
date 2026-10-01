from __future__ import annotations

import ipaddress
import time
from datetime import datetime, timezone

from .models import PacketRecord


def _direction(src: str, dst: str) -> str:
    try:
        src_private = ipaddress.ip_address(src).is_private
        dst_private = ipaddress.ip_address(dst).is_private
    except ValueError:
        return "local"
    if src_private and not dst_private:
        return "outbound"
    if not src_private and dst_private:
        return "inbound"
    if src_private and dst_private:
        return "internal"
    return "external"


def parse_scapy_packet(packet) -> PacketRecord:
    """Convert a Scapy packet to privacy-conscious metadata."""
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether

    timestamp = float(getattr(packet, "time", time.time()))
    captured_at = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    src = "unknown"
    dst = "unknown"
    src_mac = None
    dst_mac = None
    src_port = None
    dst_port = None
    transport = "OTHER"
    protocol = "OTHER"
    info = packet.summary()
    flags = None
    dns_query = None

    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
    if packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src, dst = packet[IPv6].src, packet[IPv6].dst

    if packet.haslayer(ARP):
        arp = packet[ARP]
        protocol = transport = "ARP"
        src, dst = arp.psrc or src, arp.pdst or dst
        src_mac = arp.hwsrc or src_mac
        info = f"ARP {'request' if int(arp.op) == 1 else 'reply'}: {src} is at {src_mac}"
    elif packet.haslayer(TCP):
        tcp = packet[TCP]
        transport = "TCP"
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        flags = str(tcp.flags)
        service_port = dst_port if dst_port < 49152 else src_port
        protocol = {
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "TLS",
        }.get(service_port, "TCP")
        info = f"{src_port} → {dst_port}  Flags [{flags}]"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        transport = "UDP"
        src_port, dst_port = int(udp.sport), int(udp.dport)
        protocol = "DNS" if 53 in {src_port, dst_port} else "UDP"
        info = f"{src_port} → {dst_port}"
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        protocol = transport = "ICMP"
        info = f"ICMP type={icmp.type} code={icmp.code}"
    elif packet.haslayer(IPv6):
        protocol = "IPv6"
        transport = "IPv6"

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        protocol = "DNS"
        raw_name = packet[DNSQR].qname
        dns_query = raw_name.decode("utf-8", errors="replace") if isinstance(raw_name, bytes) else str(raw_name)
        info = f"DNS query: {dns_query}"

    return PacketRecord(
        timestamp=timestamp,
        captured_at=captured_at,
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        transport=transport,
        length=len(packet),
        direction=_direction(src, dst),
        info=info[:300],
        tcp_flags=flags,
        dns_query=dns_query,
        src_mac=src_mac,
        dst_mac=dst_mac,
    )
