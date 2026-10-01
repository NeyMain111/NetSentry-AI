from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .demo import DemoTrafficGenerator
from .detector import ThreatDetector
from .models import PacketRecord
from .packet_parser import parse_scapy_packet
from .store import TrafficStore


class PacketProcessor:
    def __init__(self, store: TrafficStore, detector: ThreatDetector) -> None:
        self.store = store
        self.detector = detector

    def process_record(self, record: PacketRecord) -> PacketRecord:
        packet = self.store.add_packet(record)
        for alert in self.detector.inspect(packet):
            self.store.add_alert(alert, packet)
        return packet

    def process_scapy(self, packet) -> None:
        try:
            self.process_record(parse_scapy_packet(packet))
        except Exception:
            # A malformed or unsupported packet must not stop the capture thread.
            return


class CaptureController:
    def __init__(self, processor: PacketProcessor) -> None:
        self.processor = processor
        self._lock = threading.RLock()
        self._sniffer = None
        self._demo_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.mode: str | None = None
        self.interface: str | None = None
        self.started_at: str | None = None
        self.last_error: str | None = None

    @property
    def running(self) -> bool:
        with self._lock:
            return self._sniffer is not None or (self._demo_thread is not None and self._demo_thread.is_alive())

    def status(self) -> dict:
        return {
            "running": self.running,
            "mode": self.mode,
            "interface": self.interface,
            "started_at": self.started_at,
            "last_error": self.last_error,
        }

    @staticmethod
    def interfaces() -> list[str]:
        try:
            return [name for _, name in socket.if_nameindex()]
        except OSError:
            return []

    def start(self, mode: str, interface: str | None = None) -> None:
        with self._lock:
            if self.running:
                raise RuntimeError("A capture is already running.")
            self.last_error = None
            self.mode = mode
            self.interface = interface
            self.started_at = datetime.now(timezone.utc).isoformat()
            self._stop_event.clear()

            if mode == "demo":
                self._demo_thread = threading.Thread(target=self._demo_loop, name="netsentry-demo", daemon=True)
                self._demo_thread.start()
                return

            if mode != "live":
                raise RuntimeError(f"Unsupported capture mode: {mode}")
            try:
                from scapy.sendrecv import AsyncSniffer

                self._sniffer = AsyncSniffer(iface=interface or None, prn=self.processor.process_scapy, store=False)
                self._sniffer.start()
            except Exception as exc:
                self._sniffer = None
                self.last_error = str(exc)
                raise RuntimeError(
                    "Live capture could not start. Run NetSentry with sudo/capture capabilities and verify the interface."
                ) from exc

    def stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            if self._sniffer is not None:
                try:
                    self._sniffer.stop()
                except Exception as exc:
                    self.last_error = str(exc)
                finally:
                    self._sniffer = None
            self._demo_thread = None
            self.mode = None
            self.interface = None

    def _demo_loop(self) -> None:
        generator = DemoTrafficGenerator()
        while not self._stop_event.is_set():
            self.processor.process_record(generator.normal_packet())
            for record in generator.attack_burst():
                self.processor.process_record(record)
            self._stop_event.wait(0.22)

    def import_pcap(self, path: Path, limit: int = 10000) -> int:
        try:
            from scapy.utils import PcapReader
        except ImportError as exc:
            raise RuntimeError("Scapy is required to import PCAP files.") from exc

        processed = 0
        with PcapReader(str(path)) as reader:
            for packet in reader:
                self.processor.process_scapy(packet)
                processed += 1
                if processed >= limit:
                    break
        return processed

