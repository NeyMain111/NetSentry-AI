from __future__ import annotations

import math
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

from .models import AlertRecord, PacketRecord, Severity


def _utc_now(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


class ThreatDetector:
    """Small explainable IDS engine based on sliding time windows."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._syn_by_source: dict[str, deque[tuple[float, str, int | None]]] = defaultdict(deque)
        self._syn_by_target: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._icmp_by_source: dict[str, deque[float]] = defaultdict(deque)
        self._arp_table: dict[str, str] = {}
        self._cooldown: dict[str, float] = {}

    def reset(self) -> None:
        with self._lock:
            self._syn_by_source.clear()
            self._syn_by_target.clear()
            self._icmp_by_source.clear()
            self._arp_table.clear()
            self._cooldown.clear()

    @staticmethod
    def _trim(events: deque, minimum_time: float) -> None:
        while events and events[0][0] < minimum_time:
            events.popleft()

    def _allowed(self, key: str, timestamp: float, cooldown: float = 12.0) -> bool:
        previous = self._cooldown.get(key, 0.0)
        if timestamp - previous < cooldown:
            return False
        self._cooldown[key] = timestamp
        return True

    @staticmethod
    def _alert(
        packet: PacketRecord,
        alert_type: str,
        title: str,
        description: str,
        severity: Severity,
        evidence: dict[str, str | int | float],
        recommendation: str,
    ) -> AlertRecord:
        return AlertRecord(
            timestamp=packet.timestamp,
            detected_at=_utc_now(packet.timestamp),
            type=alert_type,
            title=title,
            description=description,
            severity=severity,
            source=packet.src,
            destination=packet.dst,
            packet_id=packet.id,
            evidence=evidence,
            recommendation=recommendation,
        )

    def inspect(self, packet: PacketRecord) -> list[AlertRecord]:
        alerts: list[AlertRecord] = []
        now = packet.timestamp

        with self._lock:
            flags = packet.tcp_flags or ""
            is_initial_syn = packet.transport == "TCP" and "S" in flags and "A" not in flags
            if is_initial_syn:
                source_events = self._syn_by_source[packet.src]
                source_events.append((now, packet.dst, packet.dst_port))
                self._trim(source_events, now - 10.0)
                unique_ports = {(dst, port) for _, dst, port in source_events}
                if (
                    len(source_events) >= 18
                    and len(unique_ports) >= 10
                    and self._allowed(f"port_scan:{packet.src}", now)
                ):
                    alerts.append(
                        self._alert(
                            packet,
                            "port_scan",
                            "Possible TCP port scan",
                            f"{packet.src} sent SYN packets to {len(unique_ports)} distinct destination ports in 10 seconds.",
                            "high",
                            {"syn_packets": len(source_events), "unique_targets": len(unique_ports), "window_seconds": 10},
                            "Verify the source host, block it temporarily if unknown, and review firewall logs for follow-up connections.",
                        )
                    )

                target_events = self._syn_by_target[packet.dst]
                target_events.append((now, packet.src))
                self._trim(target_events, now - 5.0)
                if len(target_events) >= 35 and self._allowed(f"syn_flood:{packet.dst}", now):
                    alerts.append(
                        self._alert(
                            packet,
                            "syn_flood",
                            "Possible SYN flood",
                            f"{len(target_events)} incomplete connection attempts targeted {packet.dst} in 5 seconds.",
                            "critical",
                            {"syn_packets": len(target_events), "window_seconds": 5},
                            "Enable SYN cookies or rate limiting, identify top sources, and isolate the target if service availability is affected.",
                        )
                    )

            if packet.transport == "ICMP":
                icmp_events = self._icmp_by_source[packet.src]
                icmp_events.append(now)
                while icmp_events and icmp_events[0] < now - 5.0:
                    icmp_events.popleft()
                if len(icmp_events) >= 40 and self._allowed(f"icmp_flood:{packet.src}", now):
                    alerts.append(
                        self._alert(
                            packet,
                            "icmp_flood",
                            "Possible ICMP flood",
                            f"{packet.src} generated {len(icmp_events)} ICMP packets in 5 seconds.",
                            "high",
                            {"icmp_packets": len(icmp_events), "window_seconds": 5},
                            "Apply ICMP rate limits and check whether the source is a legitimate monitoring system.",
                        )
                    )

            if packet.dns_query:
                query = packet.dns_query.rstrip(".")
                labels = query.split(".")
                longest = max((len(label) for label in labels), default=0)
                entropy = self._entropy("".join(labels))
                if (
                    (len(query) >= 70 or longest >= 40)
                    and entropy >= 3.5
                    and self._allowed(f"dns_tunnel:{packet.src}", now, cooldown=20.0)
                ):
                    alerts.append(
                        self._alert(
                            packet,
                            "dns_tunnel",
                            "Suspicious DNS query",
                            "The DNS name is unusually long and has high character entropy, which can indicate DNS tunnelling.",
                            "medium",
                            {"query_length": len(query), "longest_label": longest, "entropy": round(entropy, 2)},
                            "Inspect repeated queries from this host, validate the destination domain, and restrict DNS traffic to approved resolvers.",
                        )
                    )

            if packet.protocol == "ARP" and packet.src and packet.src_mac:
                previous_mac = self._arp_table.get(packet.src)
                if previous_mac and previous_mac != packet.src_mac and self._allowed(f"arp_spoof:{packet.src}", now):
                    alerts.append(
                        self._alert(
                            packet,
                            "arp_spoof",
                            "ARP address changed",
                            f"IP {packet.src} was previously associated with {previous_mac}, but is now advertised by {packet.src_mac}.",
                            "critical",
                            {"previous_mac": previous_mac, "new_mac": packet.src_mac},
                            "Confirm the legitimate MAC address, isolate the conflicting device, and consider static ARP or switch port security.",
                        )
                    )
                self._arp_table[packet.src] = packet.src_mac

            if packet.dst_port in {23, 2323, 4444, 5555, 31337} and self._allowed(
                f"risky_port:{packet.src}:{packet.dst}:{packet.dst_port}", now, cooldown=30.0
            ):
                alerts.append(
                    self._alert(
                        packet,
                        "risky_service",
                        "Connection to a risky service port",
                        f"Traffic was observed to destination port {packet.dst_port}, commonly associated with insecure services or backdoors.",
                        "low",
                        {"destination_port": packet.dst_port},
                        "Confirm that the service is authorised and replace clear-text protocols such as Telnet with encrypted alternatives.",
                    )
                )

        return alerts

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        probabilities = [value.count(char) / len(value) for char in set(value)]
        return -sum(p * math.log2(p) for p in probabilities)

