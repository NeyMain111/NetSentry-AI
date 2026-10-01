import unittest

from netsentry.capture import PacketProcessor
from netsentry.demo import DemoTrafficGenerator
from netsentry.detector import ThreatDetector
from netsentry.store import TrafficStore


class PipelineTests(unittest.TestCase):
    def test_demo_pipeline_assigns_ids_and_updates_stats(self) -> None:
        store = TrafficStore()
        processor = PacketProcessor(store, ThreatDetector())
        generator = DemoTrafficGenerator()
        for _ in range(4):
            processor.process_record(generator.normal_packet())
        result = store.snapshot()
        self.assertEqual(result["stats"]["total_packets"], 4)
        self.assertEqual([item["id"] for item in result["packets"]], [4, 3, 2, 1])
        self.assertGreater(result["stats"]["total_bytes"], 0)

    def test_protocol_and_suspicious_filters(self) -> None:
        store = TrafficStore()
        processor = PacketProcessor(store, ThreatDetector())
        generator = DemoTrafficGenerator()
        for _ in range(100):
            processor.process_record(generator.normal_packet())
            for item in generator.attack_burst():
                processor.process_record(item)
        tcp = store.snapshot(protocol="TCP")
        suspicious = store.snapshot(suspicious=True)
        self.assertTrue(tcp["packets"])
        self.assertTrue(all(item["protocol"] == "TCP" for item in tcp["packets"]))
        self.assertTrue(suspicious["packets"])
        self.assertTrue(all(item["suspicious"] for item in suspicious["packets"]))

    def test_clear_resets_counters(self) -> None:
        store = TrafficStore()
        processor = PacketProcessor(store, ThreatDetector())
        processor.process_record(DemoTrafficGenerator().normal_packet())
        store.clear()
        self.assertEqual(store.snapshot()["stats"]["total_packets"], 0)


if __name__ == "__main__":
    unittest.main()

