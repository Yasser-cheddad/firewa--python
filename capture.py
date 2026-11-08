"""
PyWall - Live packet capture mode (requires scapy + root/admin privileges)
Usage:
    sudo python capture.py                  # capture all interfaces
    sudo python capture.py -i eth0          # specific interface
    sudo python capture.py -i eth0 --bpf "tcp"   # BPF filter
"""

import argparse
import sys
import time
from firewall import Firewall, PacketInfo

fw = Firewall()

def try_import_scapy():
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
        return sniff, IP, TCP, UDP, ICMP
    except ImportError:
        print("scapy is not installed. Install it with:  pip install scapy")
        print("Note: live capture requires root/administrator privileges.")
        sys.exit(1)

def packet_callback(sniff, IP, TCP, UDP, ICMP):
    def _callback(pkt):
        if IP not in pkt:
            return

        ip = pkt[IP]
        proto = "other"
        sport = None
        dport = None

        if TCP in pkt:
            proto = "tcp"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "udp"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            proto = "icmp"

        info = PacketInfo(
            timestamp=time.time(),
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol=proto,
            src_port=sport,
            dst_port=dport,
            size=len(pkt),
        )
        action, reason = fw.process_packet(info)
        # In a real kernel-level implementation you would call
        # nfqueue.drop() / nfqueue.accept() here.
        # This demo logs the verdict but does not actually drop packets.
    return _callback

def main():
    parser = argparse.ArgumentParser(description="PyWall live capture (requires root)")
    parser.add_argument("-i", "--iface", default=None, help="Network interface (default: all)")
    parser.add_argument("--bpf", default=None, help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packet count (0=infinite)")
    args = parser.parse_args()

    sniff_fn, IP, TCP, UDP, ICMP = try_import_scapy()

    print(f"[*] Starting live capture on {'all interfaces' if not args.iface else args.iface}")
    print("[*] Press Ctrl+C to stop.\n")

    cb = packet_callback(sniff_fn, IP, TCP, UDP, ICMP)
    try:
        sniff_fn(
            iface=args.iface,
            filter=args.bpf,
            prn=cb,
            count=args.count,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Capture stopped.")
        s = fw.get_stats()
        print(f"[*] Total: {s['total']}  Allowed: {s['allowed']}  Blocked: {s['blocked']}  Rate-limited: {s['rate_limited']}")

if __name__ == "__main__":
    main()
