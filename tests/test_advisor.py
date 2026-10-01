import json
import os
import unittest
from unittest.mock import AsyncMock, patch

from netsentry.advisor import SecurityAdvisor
from netsentry.demo import DemoTrafficGenerator
from netsentry.models import AdvisorMessage
from netsentry.store import TrafficStore


class AdvisorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.store = TrafficStore()
        self.store.add_packet(DemoTrafficGenerator().normal_packet())

    def test_prompt_contains_capture_context_and_chat_history(self) -> None:
        advisor = SecurityAdvisor(
            self.store,
            lambda: {"running": True, "mode": "live", "interface": "lo"},
        )
        history = [
            AdvisorMessage(role="user", content="How many alerts are there?"),
            AdvisorMessage(role="assistant", content="There are no alerts yet."),
        ]

        messages = advisor._build_messages("What should I check next?", None, history)

        self.assertEqual(messages[-3]["content"], history[0].content)
        self.assertEqual(messages[-2]["content"], history[1].content)
        self.assertEqual(messages[-1]["content"], "What should I check next?")
        raw_context = messages[1]["content"].split("\n", 1)[1]
        context = json.loads(raw_context)
        self.assertEqual(context["capture"]["interface"], "lo")
        self.assertEqual(context["summary"]["total_packets"], 1)
        self.assertEqual(len(context["recent_packets"]), 1)
        self.assertFalse(context["context_limits"]["packet_payloads_available"])

    async def test_local_model_response_is_returned(self) -> None:
        advisor = SecurityAdvisor(self.store)
        advisor._ask_ollama = AsyncMock(return_value="A context-aware answer")
        history = [AdvisorMessage(role="user", content="Earlier question")]

        response = await advisor.answer("Follow-up", history=history)

        self.assertEqual(response.provider, "ollama")
        self.assertEqual(response.answer, "A context-aware answer")
        advisor._ask_ollama.assert_awaited_once_with("Follow-up", None, history)

    async def test_disabled_local_model_uses_labelled_fallback(self) -> None:
        with patch.dict(os.environ, {"NETSENTRY_USE_OLLAMA": "0"}):
            advisor = SecurityAdvisor(self.store)

        response = await advisor.answer("Are there threats?")
        status = await advisor.status()

        self.assertEqual(response.provider, "rules")
        self.assertIn("disabled", response.notice.lower())
        self.assertEqual(status.state, "disabled")


if __name__ == "__main__":
    unittest.main()
