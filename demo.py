"""
PyWall Demo - Loads example rules and runs a packet simulation.
Run with:  python demo.py
"""

import time
from firewall import Firewall, PacketInfo

def run_demo():
    fw = Firewall(config_path="demo_config.json")

    print("\n=== PyWall Demo ===\n")

    # ------------------------------------------------------------------ #
    # Add some example rules                                              #
    # ------------------------------------------------------------------ #
    print("[1] Adding example rules...\n")

    fw.add_rule("block",  "tcp", src_ip="*",              dst_port=23,  description="Block Telnet")
    fw.add_rule("allow",  "tcp", src_ip="*",              dst_port=22,  description="Allow SSH")
    fw.add_rule("allow",  "tcp", src_ip="*",              dst_port=80,  description="Allow HTTP")
    fw.add_rule("allow",  "tcp", src_ip="*",              dst_port=443, description="Allow HTTPS")
    fw.add_rule("block",  "tcp", src_ip="192.168.99.0/24",             description="Block suspicious subnet")
    fw.add_rule("allow",  "udp", src_ip="*",              dst_port=53,  description="Allow DNS")
    fw.add_rule("allow",  "icmp",                                       description="Allow ICMP/ping")

    # Rate limit: max 5 packets per 10 seconds from any single IP
    fw.add_rate_rule(src_ip="*", max_packets=5, window_seconds=10, description="5 pkt/10s global limit")

    print("[2] Sending test packets...\n")

    packets = [
        PacketInfo(time.time(), "10.0.0.5",      "10.0.0.1", "tcp",  50001, 443),   # expect: allow
        PacketInfo(time.time(), "10.0.0.5",      "10.0.0.1", "tcp",  50002, 23),    # expect: block (telnet)
        PacketInfo(time.time(), "192.168.99.10", "10.0.0.1", "tcp",  50003, 80),    # expect: block (subnet)
        PacketInfo(time.time(), "8.8.8.8",       "10.0.0.1", "udp",  None,  53),    # expect: allow (DNS)
        PacketInfo(time.time(), "1.2.3.4",       "10.0.0.1", "icmp", None,  None),  # expect: allow (ICMP)
        PacketInfo(time.time(), "5.5.5.5",       "10.0.0.1", "tcp",  60001, 22),    # expect: allow (SSH)
        # These next packets from 5.5.5.5 should trigger the rate limiter
        PacketInfo(time.time(), "5.5.5.5",       "10.0.0.1", "tcp",  60002, 80),
        PacketInfo(time.time(), "5.5.5.5",       "10.0.0.1", "tcp",  60003, 80),
        PacketInfo(time.time(), "5.5.5.5",       "10.0.0.1", "tcp",  60004, 80),
        PacketInfo(time.time(), "5.5.5.5",       "10.0.0.1", "tcp",  60005, 80),
        PacketInfo(time.time(), "5.5.5.5",       "10.0.0.1", "tcp",  60006, 80),   # rate limit!
    ]

    results = []
    for pkt in packets:
        action, reason = fw.process_packet(pkt)
        results.append((pkt, action, reason))

    print("\n[3] Results summary:\n")
    for pkt, action, reason in results:
        marker = "✓" if action == "allow" else "✗"
        print(f"  {marker} [{action.upper():5}] {pkt.src_ip}:{pkt.src_port or '*'} -> "
              f"{pkt.dst_ip}:{pkt.dst_port or '*'} ({pkt.protocol}) | {reason}")

    print("\n[4] Final stats:\n")
    s = fw.get_stats()
    print(f"  Total     : {s['total']}")
    print(f"  Allowed   : {s['allowed']}")
    print(f"  Blocked   : {s['blocked']}")
    print(f"  Rate-lim  : {s['rate_limited']}")
    print()

if __name__ == "__main__":
    run_demo()
