import unittest
from datetime import datetime, timezone

from netsentry.detector import ThreatDetector
from netsentry.models import PacketRecord


def packet(timestamp: float, **overrides) -> PacketRecord:
    defaults = {
        "timestamp": timestamp,
        "captured_at": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "src": "10.0.0.5",
        "dst": "10.0.0.20",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "TCP",
        "transport": "TCP",
        "length": 60,
        "direction": "internal",
        "info": "test",
        "tcp_flags": "S",
    }
    defaults.update(overrides)
    return PacketRecord(**defaults)


class ThreatDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = ThreatDetector()

    def test_tcp_port_scan_is_detected(self) -> None:
        alerts = []
        for index in range(18):
            current = packet(1000 + index * 0.1, id=index + 1, dst_port=20 + index)
            alerts.extend(self.detector.inspect(current))
        self.assertIn("port_scan", [alert.type for alert in alerts])

    def test_normal_syn_does_not_raise_alert(self) -> None:
        alerts = []
        for index in range(5):
            alerts.extend(self.detector.inspect(packet(1000 + index, id=index + 1, dst_port=443)))
        self.assertEqual(alerts, [])

    def test_high_entropy_long_dns_query_is_detected(self) -> None:
        query = "a8f91ce32b740d56e18c92a74f0b5d638e21c497ab03f65d72e91a84f6c30b27.example.net."
        item = packet(
            1000,
            id=1,
            protocol="DNS",
            transport="UDP",
            src_port=53001,
            dst_port=53,
            tcp_flags=None,
            dns_query=query,
        )
        alerts = self.detector.inspect(item)
        self.assertEqual([alert.type for alert in alerts], ["dns_tunnel"])

    def test_arp_address_change_is_detected(self) -> None:
        first = packet(1000, id=1, protocol="ARP", transport="ARP", src="10.0.0.1", src_mac="00:11:22:33:44:55", tcp_flags=None)
        second = packet(1001, id=2, protocol="ARP", transport="ARP", src="10.0.0.1", src_mac="aa:bb:cc:dd:ee:ff", tcp_flags=None)
        self.assertEqual(self.detector.inspect(first), [])
        alerts = self.detector.inspect(second)
        self.assertEqual([alert.type for alert in alerts], ["arp_spoof"])

    def test_risky_port_alert_has_cooldown(self) -> None:
        first = self.detector.inspect(packet(1000, id=1, dst_port=4444))
        second = self.detector.inspect(packet(1001, id=2, dst_port=4444))
        self.assertIn("risky_service", [alert.type for alert in first])
        self.assertNotIn("risky_service", [alert.type for alert in second])


if __name__ == "__main__":
    unittest.main()

