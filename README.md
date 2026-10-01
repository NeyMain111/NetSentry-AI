# NetSentry AI

NetSentry AI is a local network traffic monitor built for a cybersecurity internship project. It captures packet metadata, groups traffic by protocol, detects several suspicious patterns with explainable rules, and provides defensive guidance through a local AI advisor.

The interface is inspired by packet-analysis and security-operations tools, while keeping the scope appropriate for an educational project. NetSentry does **not** store packet payloads.

## Main features

- live packet capture from a selected interface with Scapy/libpcap;
- safe synthetic demo mode that works without root permissions;
- PCAP, PCAPNG and CAP import (up to 100 MB / 10,000 packets);
- protocol identification for TCP, UDP, DNS, HTTP, TLS, SSH, FTP, Telnet, ICMP, ARP and IPv6;
- filtering by protocol, address, details and suspicious status;
- explainable rules for TCP port scans, SYN floods, ICMP floods, suspicious DNS queries, ARP address changes and risky service ports;
- context-aware local Ollama advisor with conversation memory and an explicitly labelled rule-based fallback;
- CSV export of captured metadata;
- responsive dashboard with packet details, traffic rate and protocol distribution.

## Quick start on Kali Linux or Ubuntu

1. Install the operating-system capture dependency:

       sudo apt update
       sudo apt install -y python3-venv libpcap-dev

2. Create a virtual environment and install the project:

       python3 -m venv .venv
       source .venv/bin/activate
       pip install -e .

3. Start in safe demo mode:

       netsentry --demo

4. Open `http://127.0.0.1:8000` in a browser.

Demo mode generates synthetic metadata and deliberately produces a few detectable patterns. It is the easiest way to demonstrate every interface component.

After installing `python3-venv`, the same setup and launch can be performed with one command from the project directory:

    bash run_demo.sh

## Live packet capture

Packet capture normally requires elevated privileges on Linux:

    sudo .venv/bin/netsentry

Open the dashboard, choose **Live interface**, select an interface such as `eth0` or `wlan0`, and start capture. Only monitor a network and devices that you own or are explicitly authorised to inspect.

## Local AI assistant with Ollama

The full advisor uses a local language model. It receives summary statistics, the selected alert, up to 20 recent alerts, up to 30 recent packet-metadata records, and the last 12 chat messages. Packet payloads are never sent because NetSentry does not store them.

Install Ollama on Kali Linux or Ubuntu using the official installer, start its service, and download the multilingual model:

    curl -fsSL https://ollama.com/install.sh | sh
    sudo systemctl enable --now ollama
    ollama pull qwen2.5:3b

Verify the local model service:

    ollama list
    curl -s http://127.0.0.1:11434/api/tags

Then launch NetSentry with local AI enabled:

    sudo env -u NETSENTRY_AUTO_DEMO \
      NETSENTRY_USE_OLLAMA=1 \
      NETSENTRY_OLLAMA_MODEL=qwen2.5:3b \
      .venv/bin/netsentry

The advisor badge must show `qwen2.5:3b · local AI`. The first answer can take longer while the model is loaded into memory. Later answers reuse the model for ten minutes.

For a stronger model on a computer with more memory, download and select the 7B version:

    ollama pull qwen2.5:7b
    sudo env -u NETSENTRY_AUTO_DEMO \
      NETSENTRY_USE_OLLAMA=1 \
      NETSENTRY_OLLAMA_MODEL=qwen2.5:7b \
      .venv/bin/netsentry

The 3B model download is about 1.9 GB. It is the default because it is practical on a typical internship laptop and supports Russian and English. The 7B model is more capable but needs more RAM and is slower on CPU-only systems.

If Ollama is stopped or the selected model is missing, the UI clearly shows `Ollama offline`, `Model not installed`, or `Rule fallback`. The fallback keeps basic explanations available, but it is intentionally not presented as a language model.

Configuration variables:

- `NETSENTRY_USE_OLLAMA=0` disables local AI.
- `NETSENTRY_OLLAMA_MODEL` selects an installed model.
- `NETSENTRY_OLLAMA_URL` changes the default endpoint `http://127.0.0.1:11434`.
- `NETSENTRY_OLLAMA_TIMEOUT` changes the response timeout in seconds (default: 120).

To test conversation memory, ask an alert-specific question and then a refinement:

    Explain this alert and tell me what to investigate first.
    Give me five additional recommendations without repeating the previous ones.

The second answer should use both the selected alert and the earlier exchange.

### Limited fallback mode

The advisor can still work without a language model by using event-specific defensive templates. This mode is deliberately labelled `Rule fallback` and does not provide flexible conversation:

    NETSENTRY_USE_OLLAMA=0 .venv/bin/netsentry

## Tests

The core detector and processing pipeline use Python's built-in test framework:

    python -m unittest discover -s tests -v

The tests do not require root permissions and do not access a real interface.

## Project structure

    netsentry/
      main.py            FastAPI routes and application lifecycle
      capture.py         live capture, demo capture and PCAP import
      packet_parser.py   Scapy packet-to-metadata conversion
      detector.py        explainable sliding-window detection rules
      advisor.py         Ollama integration and offline fallback
      store.py           thread-safe in-memory metadata store
      static/             browser dashboard assets
      templates/          application page
    tests/               detector and pipeline tests
    docs/                design and internship documentation

## Scope and limitations

NetSentry is an educational monitoring tool, not a replacement for a production IDS such as Suricata or Zeek. Threshold rules can produce false positives, encrypted payloads are not inspected, state is kept in memory, and the tool currently monitors one running capture source. Every alert is an indicator that should be verified with firewall, DNS, endpoint and authentication logs.

## Responsible use

Capture traffic only where you have permission. Packet metadata can still contain sensitive addresses, hostnames and communication patterns. Keep the dashboard bound to `127.0.0.1` unless access controls are added, and remove exported data when it is no longer needed.
