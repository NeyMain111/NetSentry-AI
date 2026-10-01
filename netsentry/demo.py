from __future__ import annotations

import random
import string
import time
from datetime import datetime, timezone

from .models import PacketRecord


def _captured_at(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


class DemoTrafficGenerator:
    """Produces safe synthetic metadata so the dashboard can be demonstrated without root."""

    def __init__(self, seed: int = 42) -> None:
        self.random = random.Random(seed)
        self.counter = 0

    def normal_packet(self) -> PacketRecord:
        self.counter += 1
        now = time.time()
        source = f"192.168.1.{self.random.randint(2, 80)}"
        destination = self.random.choice(["1.1.1.1", "8.8.8.8", "142.250.183.78", "192.168.1.1"])
        protocol = self.random.choices(["TLS", "DNS", "TCP", "UDP", "ICMP", "HTTP"], [35, 22, 15, 10, 8, 10])[0]
        src_port = self.random.randint(49152, 65535)
        port_map = {"TLS": 443, "DNS": 53, "HTTP": 80, "TCP": 22, "UDP": 123, "ICMP": None}
        dst_port = port_map[protocol]
        transport = "TCP" if protocol in {"TLS", "HTTP", "TCP"} else ("UDP" if protocol in {"DNS", "UDP"} else "ICMP")
        flags = "PA" if transport == "TCP" else None
        query = self.random.choice(["example.com.", "updates.example.net.", "time.google.com."]) if protocol == "DNS" else None
        info = f"{src_port} → {dst_port}" if dst_port else "ICMP echo request"
        if query:
            info = f"DNS query: {query}"
        return PacketRecord(
            timestamp=now,
            captured_at=_captured_at(now),
            src=source,
            dst=destination,
            src_port=src_port if transport != "ICMP" else None,
            dst_port=dst_port,
            protocol=protocol,
            transport=transport,
            length=self.random.randint(64, 1450),
            direction="outbound" if destination != "192.168.1.1" else "internal",
            info=info,
            tcp_flags=flags,
            dns_query=query,
        )

    def attack_burst(self) -> list[PacketRecord]:
        """Return an occasional deterministic sequence that triggers explainable rules."""
        phase = self.counter % 120
        now = time.time()
        if phase in range(28, 33):
            records = []
            for index in range(20):
                port = 20 + index
                timestamp = now + index / 1000
                records.append(
                    PacketRecord(
                        timestamp=timestamp,
                        captured_at=_captured_at(timestamp),
                        src="10.10.5.44",
                        dst="192.168.1.20",
                        src_port=40000 + index,
                        dst_port=port,
                        protocol="TCP",
                        transport="TCP",
                        length=60,
                        direction="internal",
                        info=f"{40000 + index} → {port}  Flags [S]",
                        tcp_flags="S",
                    )
                )
            return records
        if phase == 65:
            token = "".join(self.random.choice(string.ascii_lowercase + string.digits) for _ in range(58))
            query = f"{token}.telemetry-example.net."
            return [
                PacketRecord(
                    timestamp=now,
                    captured_at=_captured_at(now),
                    src="192.168.1.37",
                    dst="8.8.8.8",
                    src_port=53012,
                    dst_port=53,
                    protocol="DNS",
                    transport="UDP",
                    length=148,
                    direction="outbound",
                    info=f"DNS query: {query}",
                    dns_query=query,
                )
            ]
        if phase == 92:
            return [
                PacketRecord(
                    timestamp=now,
                    captured_at=_captured_at(now),
                    src="192.168.1.51",
                    dst="192.168.1.99",
                    src_port=51000,
                    dst_port=4444,
                    protocol="TCP",
                    transport="TCP",
                    length=60,
                    direction="internal",
                    info="51000 → 4444  Flags [S]",
                    tcp_flags="S",
                )
            ]
        return []

