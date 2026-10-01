# Five-minute demonstration guide

1. Start the project with `netsentry --demo` and open the dashboard.
2. Explain the four summary cards and the live packet-rate chart.
3. Use protocol chips to show DNS, TLS, TCP and other traffic separately.
4. Search for `10.10.5.44` to isolate the synthetic scan source.
5. Enable **Alerts only** and open a highlighted packet to show retained metadata.
6. In **Threat alerts**, select **Ask AI** on the port-scan or SYN-flood finding.
7. Confirm that the advisor badge shows `qwen2.5:3b · local AI`, then ask a follow-up such as “Give me more recommendations without repeating the previous answer.”
8. Explain that the model sees recent metadata and conversation history, while packet payloads remain unavailable.
9. Stop capture, import a permitted PCAP file if available, and export the results as CSV.

Expected demo findings appear periodically: port scan/SYN flood first, then a suspicious DNS query and a connection to port 4444.

If the badge shows `Rule fallback`, `Ollama offline`, or `Model not installed`, complete the Ollama setup in `README.md` before presenting the AI functionality.
