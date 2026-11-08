"""
PyWall CLI - Interactive command-line interface for the firewall.
Usage:
    python cli.py                  # interactive shell
    python cli.py --help           # list commands
"""

import argparse
import sys
import textwrap
from firewall import Firewall, PacketInfo
from ai_model import AIModel
import time

# ANSI colours
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
 ██████╗ ██╗   ██╗██╗    ██╗ █████╗ ██╗     ██╗
 ██╔══██╗╚██╗ ██╔╝██║    ██║██╔══██╗██║     ██║
 ██████╔╝ ╚████╔╝ ██║ █╗ ██║███████║██║     ██║
 ██╔═══╝   ╚██╔╝  ██║███╗██║██╔══██║██║     ██║
 ██║        ██║   ╚███╔███╔╝██║  ██║███████╗███████╗
 ╚═╝        ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
{RESET}{YELLOW}  Cross-Platform Packet Filter Firewall  v1.0{RESET}
"""

fw = Firewall()

# --------------------------------------------------------------------------- #
#  Helpers                                                                    #
# --------------------------------------------------------------------------- #

def col(text, color):
    return f"{color}{text}{RESET}"

def print_table(headers, rows, widths=None):
    if not widths:
        widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                  for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    sep = "  ".join("-" * w for w in widths)
    print(col(fmt.format(*headers), BOLD))
    print(sep)
    for row in rows:
        print(fmt.format(*[str(c) for c in row]))

# --------------------------------------------------------------------------- #
#  Command handlers                                                           #
# --------------------------------------------------------------------------- #

def cmd_rules(args):
    rules = fw.list_rules()
    if not rules:
        print("No filter rules defined.")
        return
    rows = []
    for r in rules:
        status = col("ON ", GREEN) if r.enabled else col("OFF", RED)
        action = col(r.action.upper(), GREEN if r.action == "allow" else RED)
        rows.append([
            r.id, status, action,
            r.protocol, r.src_ip,
            r.src_port or "*", r.dst_ip,
            r.dst_port or "*", r.hits,
            r.description[:30]
        ])
    print_table(
        ["ID", "On?", "Action", "Proto", "Src IP", "SPort", "Dst IP", "DPort", "Hits", "Description"],
        rows, [4, 5, 7, 6, 20, 6, 20, 6, 6, 30]
    )

def cmd_rate_rules(args):
    rrs = fw.list_rate_rules()
    if not rrs:
        print("No rate-limit rules defined.")
        return
    rows = []
    for r in rrs:
        status = col("ON ", GREEN) if r.enabled else col("OFF", RED)
        rows.append([r.id, status, r.src_ip, r.max_packets,
                     r.window_seconds, r.action, r.description[:30]])
    print_table(
        ["ID", "On?", "Src IP", "Max Pkts", "Window(s)", "Action", "Description"],
        rows, [4, 5, 20, 9, 10, 7, 30]
    )

def cmd_add(args):
    rule = fw.add_rule(
        action=args.action,
        protocol=args.protocol,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        description=args.description or "",
    )
    print(col(f"✓ Rule #{rule.id} added.", GREEN))

def cmd_remove(args):
    if fw.remove_rule(args.id):
        print(col(f"✓ Rule #{args.id} removed.", GREEN))
    else:
        print(col(f"✗ Rule #{args.id} not found.", RED))

def cmd_toggle(args):
    result = fw.toggle_rule(args.id)
    if result is None:
        print(col(f"✗ Rule #{args.id} not found.", RED))
    else:
        state = col("enabled", GREEN) if result else col("disabled", YELLOW)
        print(f"Rule #{args.id} is now {state}.")

def cmd_add_rate(args):
    rr = fw.add_rate_rule(
        src_ip=args.src_ip,
        max_packets=args.max_packets,
        window_seconds=args.window,
        action=args.action,
        description=args.description or "",
    )
    print(col(f"✓ Rate rule #{rr.id} added.", GREEN))

def cmd_remove_rate(args):
    if fw.remove_rate_rule(args.id):
        print(col(f"✓ Rate rule #{args.id} removed.", GREEN))
    else:
        print(col(f"✗ Rate rule #{args.id} not found.", RED))

def cmd_stats(args):
    s = fw.get_stats()
    total = s["total"] or 1
    print(f"\n  {BOLD}Packet Statistics{RESET}")
    print(f"  Total processed : {s['total']}")
    print(f"  Allowed         : {col(s['allowed'], GREEN)}  ({100*s['allowed']//total}%)")
    print(f"  Blocked         : {col(s['blocked'], RED)}  ({100*s['blocked']//total}%)")
    print(f"  Rate-limited    : {col(s['rate_limited'], YELLOW)}  ({100*s['rate_limited']//total}%)")
    print()

def cmd_policy(args):
    fw.default_policy = args.policy
    fw.save_config()
    color = GREEN if args.policy == "allow" else RED
    print(f"Default policy set to {col(args.policy.upper(), color)}.")

def cmd_test(args):
    """Simulate a packet and show what the firewall would do."""
    pkt = PacketInfo(
        timestamp=time.time(),
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        protocol=args.protocol,
        src_port=args.src_port,
        dst_port=args.dst_port,
    )
    action, reason = fw.process_packet(pkt)
    color = GREEN if action == "allow" else RED
    print(f"\n  Result  : {col(action.upper(), color)}")
    print(f"  Reason  : {reason}\n")


def cmd_train_ai(args):
    """Train a simple AI model from simulated firewall decisions."""
    import random

    training_fw = Firewall(args.config) if args.config else fw
    samples = []
    labels = []
    protocol_choices = ["tcp", "udp", "icmp"]
    port_choices = [None, 22, 23, 53, 80, 443, 1025, 3306, 49152, 60000]
    ip_pool = ["10.0.0.5", "192.168.1.10", "172.16.0.5", "8.8.8.8", "1.2.3.4", "192.168.99.10"]

    for _ in range(args.count):
        pkt = PacketInfo(
            timestamp=time.time(),
            src_ip=random.choice(ip_pool),
            dst_ip="10.0.0.1",
            protocol=random.choice(protocol_choices),
            src_port=random.choice(port_choices),
            dst_port=random.choice(port_choices),
            size=random.choice([64, 128, 512, 1500, 4096]),
        )
        action, _, _ = training_fw.evaluate_packet(pkt, use_ai=False)
        samples.append(pkt)
        labels.append(1 if action == "allow" else 0)

    model = AIModel()
    model.fit(samples, labels, epochs=args.epochs, lr=args.lr)
    model.save(args.output)
    if not args.config:
        fw.ai_model = model
    allow_count = sum(labels)
    block_count = len(labels) - allow_count
    print(col(
        f"✓ AI model trained on {args.count} packets "
        f"(allow={allow_count}, block={block_count}) and saved to {args.output}",
        GREEN,
    ))


def cmd_predict_ai(args):
    """Load an AI model and predict a packet verdict."""
    if fw.ai_model is None:
        try:
            fw.ai_model = AIModel.load(args.model)
        except Exception as exc:
            print(col(f"✗ Failed to load model: {exc}", RED))
            return

    pkt = PacketInfo(
        timestamp=time.time(),
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        protocol=args.protocol,
        src_port=args.src_port,
        dst_port=args.dst_port,
    )
    action, confidence = fw.ai_model.predict(pkt)
    color = GREEN if action == "allow" else RED
    print(f"\n  AI verdict : {col(action.upper(), color)}")
    print(f"  Confidence : {confidence:.2f}\n")

def cmd_load_ai(args):
    """Load and enable AI verdicts for packets without a matching rule."""
    try:
        fw.ai_model = AIModel.load(args.model)
    except Exception as exc:
        print(col(f"✗ Failed to load model: {exc}", RED))
        return
    print(col(f"✓ AI model loaded from {args.model}; enabled for unmatched packets.", GREEN))


def cmd_simulate(args):
    """Run a quick built-in simulation for demo purposes."""
    print(f"\n{YELLOW}Running simulation ({args.count} packets)...{RESET}\n")
    import random, ipaddress

    scenarios = [
        PacketInfo(time.time(), "192.168.1.50", "10.0.0.1", "tcp", 54321, 22),
        PacketInfo(time.time(), "10.10.10.10",  "10.0.0.1", "tcp", 60001, 80),
        PacketInfo(time.time(), "172.16.0.99",  "10.0.0.1", "udp", None,  53),
        PacketInfo(time.time(), "1.2.3.4",      "10.0.0.1", "tcp", 12345, 443),
        PacketInfo(time.time(), "192.168.1.1",  "10.0.0.1", "icmp", None, None),
    ]
    for i in range(args.count):
        pkt = random.choice(scenarios)
        pkt.timestamp = time.time()
        fw.process_packet(pkt)
        time.sleep(0.05)

    cmd_stats(None)

# --------------------------------------------------------------------------- #
#  Interactive shell                                                          #
# --------------------------------------------------------------------------- #

HELP_TEXT = f"""
{BOLD}Available commands:{RESET}

  {CYAN}rules{RESET}                           List all filter rules
  {CYAN}rate-rules{RESET}                      List all rate-limit rules
  {CYAN}stats{RESET}                           Show packet statistics
  {CYAN}policy [allow|block]{RESET}            Set default policy

  {CYAN}add{RESET} -a ACTION -p PROTO          Add a filter rule
      [-si SRC_IP] [-di DST_IP]
      [-sp SRC_PORT] [-dp DST_PORT]
      [-d DESCRIPTION]

  {CYAN}remove{RESET} ID                       Remove a filter rule
  {CYAN}toggle{RESET} ID                       Enable/disable a rule

  {CYAN}add-rate{RESET} -si SRC_IP             Add a rate-limit rule
      -m MAX_PKTS -w WINDOW_SECS
      [-a ACTION] [-d DESCRIPTION]

  {CYAN}remove-rate{RESET} ID                  Remove a rate-limit rule

  {CYAN}test{RESET} -si SRC -di DST            Simulate a single packet
      -p PROTO [-sp SPORT] [-dp DPORT]

  {CYAN}train-ai{RESET} [-n COUNT] [-e EPOCHS]  Train a simple AI model from generated packets
      [--lr LR] [--config FILE] [-o OUTPUT]
    {CYAN}load-ai{RESET} [-m MODEL]                Enable AI verdicts for unmatched packets
  {CYAN}predict-ai{RESET} -si SRC -di DST       Predict allow/block with the trained AI model
      -p PROTO [-sp SPORT] [-dp DPORT] [-m MODEL]

  {CYAN}simulate{RESET} [-n COUNT]             Run a demo simulation
  {CYAN}help{RESET}                            Show this help
  {CYAN}exit{RESET} / {CYAN}quit{RESET}                    Exit PyWall

{BOLD}Examples:{RESET}
  add -a block -p tcp -si 10.0.0.0/8 -dp 22 -d "Block SSH from LAN"
  add -a allow -p tcp -dp 443 -d "Allow HTTPS"
  add-rate -si "*" -m 100 -w 60 -d "Global 100 pkt/min limit"
  test -si 10.0.0.5 -di 192.168.1.1 -p tcp -dp 22
"""

def build_parser():
    main = argparse.ArgumentParser(prog="pywall", add_help=False)
    sub = main.add_subparsers(dest="cmd")

    sub.add_parser("rules")
    sub.add_parser("rate-rules")
    sub.add_parser("stats")
    sub.add_parser("help")

    p_pol = sub.add_parser("policy")
    p_pol.add_argument("policy", choices=["allow", "block"])

    p_add = sub.add_parser("add")
    p_add.add_argument("-a", "--action",   required=True, choices=["allow", "block"])
    p_add.add_argument("-p", "--protocol", required=True)
    p_add.add_argument("-si","--src-ip",   default="*",  dest="src_ip")
    p_add.add_argument("-di","--dst-ip",   default="*",  dest="dst_ip")
    p_add.add_argument("-sp","--src-port", type=int, default=None, dest="src_port")
    p_add.add_argument("-dp","--dst-port", type=int, default=None, dest="dst_port")
    p_add.add_argument("-d", "--description", default="")

    p_rm = sub.add_parser("remove")
    p_rm.add_argument("id", type=int)

    p_tog = sub.add_parser("toggle")
    p_tog.add_argument("id", type=int)

    p_ar = sub.add_parser("add-rate")
    p_ar.add_argument("-si","--src-ip",      required=True, dest="src_ip")
    p_ar.add_argument("-m", "--max-packets", required=True, type=int, dest="max_packets")
    p_ar.add_argument("-w", "--window",      required=True, type=int)
    p_ar.add_argument("-a", "--action",      default="block", choices=["allow","block"])
    p_ar.add_argument("-d", "--description", default="")

    p_rr = sub.add_parser("remove-rate")
    p_rr.add_argument("id", type=int)

    p_test = sub.add_parser("test")
    p_test.add_argument("-si","--src-ip",   required=True, dest="src_ip")
    p_test.add_argument("-di","--dst-ip",   required=True, dest="dst_ip")
    p_test.add_argument("-p", "--protocol", required=True)
    p_test.add_argument("-sp","--src-port", type=int, default=None, dest="src_port")
    p_test.add_argument("-dp","--dst-port", type=int, default=None, dest="dst_port")

    p_ai_train = sub.add_parser("train-ai")
    p_ai_train.add_argument("-n","--count", type=int, default=200, help="Number of generated training packets")
    p_ai_train.add_argument("-e","--epochs", type=int, default=400, help="Training epochs")
    p_ai_train.add_argument("--lr", type=float, default=0.1, help="Learning rate")
    p_ai_train.add_argument("--config", default=None, help="Policy config used for training labels")
    p_ai_train.add_argument("-o","--output", default="ai_model.json", help="Output model file")

    p_ai_predict = sub.add_parser("predict-ai")
    p_ai_predict.add_argument("-si","--src-ip",   required=True, dest="src_ip")
    p_ai_predict.add_argument("-di","--dst-ip",   required=True, dest="dst_ip")
    p_ai_predict.add_argument("-p", "--protocol", required=True)
    p_ai_predict.add_argument("-sp","--src-port", type=int, default=None, dest="src_port")
    p_ai_predict.add_argument("-dp","--dst-port", type=int, default=None, dest="dst_port")
    p_ai_predict.add_argument("-m","--model", default="ai_model.json", help="AI model file")

    p_ai_load = sub.add_parser("load-ai")
    p_ai_load.add_argument("-m", "--model", default="ai_model.json", help="AI model file")

    p_sim = sub.add_parser("simulate")
    p_sim.add_argument("-n","--count", type=int, default=20)

    return main

DISPATCH = {
    "rules":       cmd_rules,
    "rate-rules":  cmd_rate_rules,
    "add":         cmd_add,
    "remove":      cmd_remove,
    "toggle":      cmd_toggle,
    "add-rate":    cmd_add_rate,
    "remove-rate": cmd_remove_rate,
    "stats":       cmd_stats,
    "policy":      cmd_policy,
    "test":        cmd_test,
    "train-ai":    cmd_train_ai,
    "load-ai":     cmd_load_ai,
    "predict-ai":  cmd_predict_ai,
    "simulate":    cmd_simulate,
}

def interactive_shell():
    print(BANNER)
    print(f"  Type {CYAN}help{RESET} for available commands. Default policy: "
          f"{col(fw.default_policy.upper(), GREEN if fw.default_policy=='allow' else RED)}\n")

    parser = build_parser()

    while True:
        try:
            line = input(f"{CYAN}pywall>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not line:
            continue
        if line in ("exit", "quit"):
            print("Goodbye.")
            break
        if line == "help":
            print(HELP_TEXT)
            continue

        tokens = line.split()
        try:
            args = parser.parse_args(tokens)
        except SystemExit:
            continue

        handler = DISPATCH.get(args.cmd)
        if handler:
            try:
                handler(args)
            except Exception as e:
                print(col(f"Error: {e}", RED))
        else:
            print(col(f"Unknown command: '{args.cmd}'. Type help for usage.", YELLOW))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Non-interactive: parse and run single command
        parser = build_parser()
        args = parser.parse_args()
        handler = DISPATCH.get(args.cmd)
        if handler:
            handler(args)
    else:
        interactive_shell()
