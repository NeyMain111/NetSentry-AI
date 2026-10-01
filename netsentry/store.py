from __future__ import annotations

import csv
import io
import threading
from collections import Counter, deque

from .models import AlertRecord, PacketRecord


class TrafficStore:
    """Thread-safe in-memory store for capture metadata."""

    def __init__(self, packet_limit: int = 5000, alert_limit: int = 1000) -> None:
        self._packets: deque[PacketRecord] = deque(maxlen=packet_limit)
        self._alerts: deque[AlertRecord] = deque(maxlen=alert_limit)
        self._lock = threading.RLock()
        self._packet_id = 0
        self._alert_id = 0
        self._total_packets = 0
        self._total_bytes = 0
        self._protocols: Counter[str] = Counter()

    def add_packet(self, packet: PacketRecord) -> PacketRecord:
        with self._lock:
            self._packet_id += 1
            packet.id = self._packet_id
            self._packets.append(packet)
            self._total_packets += 1
            self._total_bytes += packet.length
            self._protocols[packet.protocol] += 1
            return packet

    def add_alert(self, alert: AlertRecord, packet: PacketRecord | None = None) -> AlertRecord:
        with self._lock:
            self._alert_id += 1
            alert.id = self._alert_id
            self._alerts.append(alert)
            if packet is not None:
                packet.suspicious = True
                packet.alert_ids.append(alert.id)
                packet.severity = alert.severity
            return alert

    def get_alert(self, alert_id: int) -> AlertRecord | None:
        with self._lock:
            return next((item for item in self._alerts if item.id == alert_id), None)

    def snapshot(
        self,
        limit: int = 250,
        protocol: str | None = None,
        suspicious: bool | None = None,
        query: str | None = None,
    ) -> dict:
        with self._lock:
            packets = list(self._packets)
            alerts = list(self._alerts)
            stats = {
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "total_alerts": self._alert_id,
                "stored_packets": len(self._packets),
                "protocols": dict(self._protocols),
            }

        if protocol and protocol.upper() != "ALL":
            packets = [p for p in packets if p.protocol == protocol.upper()]
        if suspicious is not None:
            packets = [p for p in packets if p.suspicious is suspicious]
        if query:
            needle = query.lower()
            packets = [
                p
                for p in packets
                if needle in p.src.lower()
                or needle in p.dst.lower()
                or needle in p.info.lower()
                or needle in p.protocol.lower()
            ]

        selected_packets = packets[-limit:] if limit else []
        return {
            "stats": stats,
            "packets": [p.model_dump(mode="json") for p in selected_packets][::-1],
            "alerts": [a.model_dump(mode="json") for a in alerts[-100:]][::-1],
        }

    def clear(self) -> None:
        with self._lock:
            self._packets.clear()
            self._alerts.clear()
            self._packet_id = 0
            self._alert_id = 0
            self._total_packets = 0
            self._total_bytes = 0
            self._protocols.clear()

    def to_csv(self) -> str:
        output = io.StringIO()
        fields = [
            "id",
            "captured_at",
            "src",
            "src_port",
            "dst",
            "dst_port",
            "protocol",
            "transport",
            "length",
            "direction",
            "suspicious",
            "severity",
            "info",
        ]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        with self._lock:
            for packet in self._packets:
                data = packet.model_dump()
                writer.writerow({field: data.get(field) for field in fields})
        return output.getvalue()
