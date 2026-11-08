"""
PyWall - Cross-platform Packet Filter Firewall
Core engine: packet interception, rule matching, rate limiting, logging
"""

import json
import time
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime
import os
import sys

# --------------------------------------------------------------------------- #
#  Data structures                                                             #
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    id: int
    action: str          # "allow" | "block"
    protocol: str        # "tcp" | "udp" | "icmp" | "any"
    src_ip: str          # CIDR or exact or "*"
    dst_ip: str          # CIDR or exact or "*"
    src_port: Optional[int]   # None = any
    dst_port: Optional[int]   # None = any
    description: str = ""
    enabled: bool = True
    hits: int = 0

    def to_dict(self):
        return asdict(self)

@dataclass
class RateLimitRule:
    id: int
    src_ip: str          # "*" = all IPs
    max_packets: int     # per window
    window_seconds: int
    action: str = "block"   # action when limit exceeded
    description: str = ""
    enabled: bool = True

    def to_dict(self):
        return asdict(self)

@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    size: int = 0

# --------------------------------------------------------------------------- #
#  IP matching helpers                                                         #
# --------------------------------------------------------------------------- #

import ipaddress

def ip_matches(pattern: str, ip: str) -> bool:
    """Match an IP against a pattern: '*', exact IP, or CIDR."""
    if pattern == "*":
        return True
    try:
        if "/" in pattern:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
        return ip == pattern
    except ValueError:
        return False

def port_matches(rule_port: Optional[int], pkt_port: Optional[int]) -> bool:
    if rule_port is None:
        return True
    return rule_port == pkt_port

def protocol_matches(rule_proto: str, pkt_proto: str) -> bool:
    return rule_proto == "any" or rule_proto.lower() == pkt_proto.lower()

# --------------------------------------------------------------------------- #
#  Rate limiter                                                                #
# --------------------------------------------------------------------------- #

class RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        # {ip: [(timestamp, count), ...]}
        self._buckets: dict = defaultdict(list)

    def check(self, src_ip: str, rule: RateLimitRule, record: bool = True) -> bool:
        """Return True if packet should be rate-limited (blocked).

        If record=False, the check is performed without updating the internal bucket.
        """
        if not rule.enabled:
            return False

        now = time.time()
        window_start = now - rule.window_seconds
        key = f"{rule.id}:{src_ip}"

        with self._lock:
            self._buckets[key] = [
                ts for ts in self._buckets[key] if ts > window_start
            ]
            count = len(self._buckets[key])
            if count >= rule.max_packets:
                return True   # rate limit hit
            if record:
                self._buckets[key].append(now)
            return False

# --------------------------------------------------------------------------- #
#  Firewall engine                                                             #
# --------------------------------------------------------------------------- #

class Firewall:
    DEFAULT_POLICY = "allow"   # "allow" or "block"

    def __init__(self, config_path: str = "firewall_config.json"):
        self.config_path = config_path
        self.rules: list[Rule] = []
        self.rate_rules: list[RateLimitRule] = []
        self._next_rule_id = 1
        self._next_rate_id = 1
        self._lock = threading.Lock()
        self.rate_limiter = RateLimiter()
        self.default_policy = self.DEFAULT_POLICY
        self.ai_model = None

        # Stats
        self.stats = {
            "total": 0,
            "allowed": 0,
            "blocked": 0,
            "rate_limited": 0,
        }

        # Logging
        self._setup_logging()
        self._load_config()

    # ---------------------------------------------------------------------- #
    #  Logging                                                                #
    # ---------------------------------------------------------------------- #

    def _setup_logging(self):
        os.makedirs("logs", exist_ok=True)
        fmt = "%(asctime)s [%(levelname)s] %(message)s"
        logging.basicConfig(
            level=logging.INFO,
            format=fmt,
            handlers=[
                logging.FileHandler("logs/firewall.log"),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.logger = logging.getLogger("pywall")

    def _log_packet(self, pkt: PacketInfo, action: str, reason: str):
        self.logger.info(
            "%-6s | src=%-18s dst=%-18s proto=%-5s sport=%-6s dport=%-6s | %s",
            action.upper(),
            f"{pkt.src_ip}:{pkt.src_port or '*'}",
            f"{pkt.dst_ip}:{pkt.dst_port or '*'}",
            pkt.protocol,
            str(pkt.src_port or "*"),
            str(pkt.dst_port or "*"),
            reason,
        )

    # ---------------------------------------------------------------------- #
    #  Config persistence                                                     #
    # ---------------------------------------------------------------------- #

    def _load_config(self):
        if not os.path.exists(self.config_path):
            return
        try:
            with open(self.config_path) as f:
                data = json.load(f)
            self.default_policy = data.get("default_policy", self.DEFAULT_POLICY)
            for r in data.get("rules", []):
                self.rules.append(Rule(**r))
                self._next_rule_id = max(self._next_rule_id, r["id"] + 1)
            for r in data.get("rate_rules", []):
                self.rate_rules.append(RateLimitRule(**r))
                self._next_rate_id = max(self._next_rate_id, r["id"] + 1)
            self.logger.info("Config loaded from %s", self.config_path)
        except Exception as e:
            self.logger.error("Failed to load config: %s", e)

    def save_config(self):
        data = {
            "default_policy": self.default_policy,
            "rules": [r.to_dict() for r in self.rules],
            "rate_rules": [r.to_dict() for r in self.rate_rules],
        }
        with open(self.config_path, "w") as f:
            json.dump(data, f, indent=2)
        self.logger.info("Config saved to %s", self.config_path)

    # ---------------------------------------------------------------------- #
    #  Rule management                                                        #
    # ---------------------------------------------------------------------- #

    def add_rule(self, action, protocol, src_ip="*", dst_ip="*",
                 src_port=None, dst_port=None, description="") -> Rule:
        with self._lock:
            rule = Rule(
                id=self._next_rule_id,
                action=action,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                description=description,
            )
            self.rules.append(rule)
            self._next_rule_id += 1
            self.save_config()
            self.logger.info("Rule #%d added: %s", rule.id, description or str(rule))
            return rule

    def remove_rule(self, rule_id: int) -> bool:
        with self._lock:
            before = len(self.rules)
            self.rules = [r for r in self.rules if r.id != rule_id]
            if len(self.rules) < before:
                self.save_config()
                self.logger.info("Rule #%d removed", rule_id)
                return True
            return False

    def toggle_rule(self, rule_id: int) -> Optional[bool]:
        with self._lock:
            for r in self.rules:
                if r.id == rule_id:
                    r.enabled = not r.enabled
                    self.save_config()
                    return r.enabled
            return None

    def add_rate_rule(self, src_ip, max_packets, window_seconds,
                      action="block", description="") -> RateLimitRule:
        with self._lock:
            rr = RateLimitRule(
                id=self._next_rate_id,
                src_ip=src_ip,
                max_packets=max_packets,
                window_seconds=window_seconds,
                action=action,
                description=description,
            )
            self.rate_rules.append(rr)
            self._next_rate_id += 1
            self.save_config()
            self.logger.info("Rate rule #%d added: %s", rr.id, description or str(rr))
            return rr

    def remove_rate_rule(self, rule_id: int) -> bool:
        with self._lock:
            before = len(self.rate_rules)
            self.rate_rules = [r for r in self.rate_rules if r.id != rule_id]
            if len(self.rate_rules) < before:
                self.save_config()
                return True
            return False

    # ---------------------------------------------------------------------- #
    #  Core packet processing                                                 #
    # ---------------------------------------------------------------------- #

    def evaluate_packet(self, pkt: PacketInfo, *, record_rate: bool = False,
                        use_ai: bool = True) -> tuple[str, str, Optional[Rule]]:
        """Evaluate a packet against rules without updating stats or logs."""
        # 1. Rate limiting check first
        for rr in self.rate_rules:
            if not rr.enabled:
                continue
            if ip_matches(rr.src_ip, pkt.src_ip):
                if self.rate_limiter.check(pkt.src_ip, rr, record=record_rate):
                    action = rr.action
                    reason = f"Rate limit exceeded (rule #{rr.id}: {rr.max_packets} pkts/{rr.window_seconds}s)"
                    return action, reason, None

        # 2. Match against filter rules (first match wins)
        for rule in self.rules:
            if not rule.enabled:
                continue
            if (ip_matches(rule.src_ip, pkt.src_ip) and
                    ip_matches(rule.dst_ip, pkt.dst_ip) and
                    protocol_matches(rule.protocol, pkt.protocol) and
                    port_matches(rule.src_port, pkt.src_port) and
                    port_matches(rule.dst_port, pkt.dst_port)):
                action = rule.action
                reason = f"Matched rule #{rule.id} ({rule.description or rule.action})"
                return action, reason, rule

        # 3. Use the AI verdict only when no explicit rule matched.
        if use_ai and self.ai_model is not None:
            try:
                action, allow_probability = self.ai_model.predict(pkt)
                reason = f"AI verdict: {action} (allow probability: {allow_probability:.2f})"
                return action, reason, None
            except Exception as e:
                self.logger.warning("AI inference failed; using default policy: %s", e)

        # 4. Default policy
        action = self.default_policy
        reason = f"Default policy: {action}"
        return action, reason, None

    def process_packet(self, pkt: PacketInfo) -> tuple[str, str]:
        """
        Evaluate a packet against all rules.
        Returns (action, reason): action is 'allow' or 'block'.
        """
        with self._lock:
            self.stats["total"] += 1
            action, reason, matched_rule = self.evaluate_packet(pkt, record_rate=True)
            if matched_rule is not None:
                matched_rule.hits += 1
            if action == "allow":
                self.stats["allowed"] += 1
            else:
                self.stats["blocked"] += 1
            if "Rate limit exceeded" in reason:
                self.stats["rate_limited"] += 1
            self._log_packet(pkt, action, reason)
            return action, reason

    def get_stats(self) -> dict:
        return dict(self.stats)

    def list_rules(self) -> list[Rule]:
        return list(self.rules)

    def list_rate_rules(self) -> list[RateLimitRule]:
        return list(self.rate_rules)
