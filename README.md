# PyWall — Cross-Platform Packet Filter Firewall

A Python-based packet filter firewall with a CLI, structured logging, and rate limiting / DDoS protection.

---

## Project Structure

```
firewall/
├── firewall.py     # Core engine (rules, rate limiter, packet processor)
├── cli.py          # Interactive CLI
├── capture.py      # Live packet capture via scapy (optional, needs root)
├── demo.py         # Demo script with pre-loaded rules & simulation
└── README.md
```

---

## Quick Start

### 1. Run the demo
```bash
python demo.py
```

### 2. Launch the interactive CLI
```bash
python cli.py
```

### 3. Live capture (optional — needs scapy + root)
```bash
pip install scapy
sudo python capture.py -i eth0
```

---

## CLI Usage

Once inside `python cli.py`:

```
# List rules
pywall> rules

# Add rules
pywall> add -a block -p tcp -dp 23 -d "Block Telnet"
pywall> add -a allow -p tcp -dp 443 -d "Allow HTTPS"
pywall> add -a block -p tcp -si 192.168.99.0/24 -d "Block bad subnet"

# Rate limiting: max 100 packets per 60 seconds from any IP
pywall> add-rate -si "*" -m 100 -w 60 -d "Global 100 pkt/min"

# Test a packet (simulation)
pywall> test -si 10.0.0.5 -di 10.0.0.1 -p tcp -dp 22

# Toggle / remove a rule
pywall> toggle 3
pywall> remove 3

# View stats
pywall> stats

# Set default policy
pywall> policy block

# Run built-in simulation
pywall> simulate -n 50

# Train and query the AI model
pywall> train-ai -n 500 -e 400 -o ai_model.json
pywall> load-ai -m ai_model.json
pywall> predict-ai -si 10.0.0.5 -di 10.0.0.1 -p tcp -dp 22 -m ai_model.json
```

---

## Features

| Feature | Details |
|---|---|
| **Filter rules** | Match on src/dst IP (CIDR supported), protocol, src/dst port |
| **Rate limiting** | Sliding-window rate limiter per source IP |
| **Logging** | All verdicts written to `logs/firewall.log` + stdout |
| **Persistence** | Rules saved to `firewall_config.json` automatically |
| **CLI** | Full interactive shell with argparse-based commands |
| **AI model** | Train with `train-ai`; `load-ai` enables AI verdicts for packets not matched by a rate-limit or filter rule |
| **Live capture** | Optional scapy integration (requires root) |
| **Simulation** | `test` and `simulate` commands for rule testing |

---

## Architecture

```
Packet In
    │
    ▼
Rate Limiter ──── hit? ──► configured verdict + log
    │ no
    ▼
Filter Rules (first match wins)
    │
    ├── match ──► configured verdict + log
    └── no match
         ▼
    AI Model (when loaded)
         │ unavailable
         ▼
    Default Policy (allow/block)
```

Explicit filter and rate-limit rules take precedence over the AI. When a model is loaded, its verdict is used for packets with no matching rule; otherwise the configured default policy applies. Training labels come from the static rules and default policy.

---

## Extending to Real Kernel-Level Enforcement

For actual packet dropping on Linux, replace the logging verdict in `capture.py` with **netfilter queue** calls:

```python
pip install NetfilterQueue

# In your callback:
if action == "block":
    packet.drop()
else:
    packet.accept()
```

On Windows, use **WinDivert**:
```python
pip install pydivert
```

---

## Requirements

- Python 3.10+
- No external packages required for the core engine and CLI
- `scapy` only needed for live capture mode
