import json
import ipaddress
from typing import List, Optional

class AIModel:
    """Simple logistic-regression style classifier for packet verdicts."""

    PROTOCOLS = ["tcp", "udp", "icmp", "other"]
    PORT_BUCKETS = ["none", "well_known", "registered", "dynamic"]
    SIZE_BUCKETS = ["tiny", "small", "medium", "large", "huge"]

    def __init__(self, weights: Optional[List[float]] = None, bias: float = 0.0):
        self.weights = weights
        self.bias = bias

    @staticmethod
    def _safe_ip(ip: str) -> ipaddress.IPv4Address:
        try:
            return ipaddress.ip_address(ip)
        except ValueError:
            return ipaddress.IPv4Address("0.0.0.0")

    @classmethod
    def _port_bucket(cls, port: Optional[int]) -> List[float]:
        buckets = [0.0, 0.0, 0.0, 0.0]
        if port is None:
            buckets[0] = 1.0
        elif port <= 1023:
            buckets[1] = 1.0
        elif port <= 49151:
            buckets[2] = 1.0
        else:
            buckets[3] = 1.0
        return buckets

    @classmethod
    def _size_bucket(cls, size: int) -> List[float]:
        buckets = [0.0] * len(cls.SIZE_BUCKETS)
        if size <= 128:
            buckets[0] = 1.0
        elif size <= 512:
            buckets[1] = 1.0
        elif size <= 1500:
            buckets[2] = 1.0
        elif size <= 8192:
            buckets[3] = 1.0
        else:
            buckets[4] = 1.0
        return buckets

    @classmethod
    def _protocol_one_hot(cls, protocol: str) -> List[float]:
        one_hot = [0.0] * len(cls.PROTOCOLS)
        normalized = protocol.lower() if protocol else ""
        if normalized in cls.PROTOCOLS:
            one_hot[cls.PROTOCOLS.index(normalized)] = 1.0
        else:
            one_hot[cls.PROTOCOLS.index("other")] = 1.0
        return one_hot

    @staticmethod
    def _ip_flags(ip: str) -> List[float]:
        addr = AIModel._safe_ip(ip)
        return [
            1.0 if addr.is_private else 0.0,
            1.0 if addr.is_loopback else 0.0,
            1.0 if addr.is_multicast else 0.0,
            1.0 if addr.is_unspecified else 0.0,
            1.0 if addr.is_reserved else 0.0,
            1.0 if addr.is_global else 0.0,
        ]

    @classmethod
    def extract_features(cls, packet) -> List[float]:
        proto = cls._protocol_one_hot(packet.protocol)
        src_ports = cls._port_bucket(packet.src_port)
        dst_ports = cls._port_bucket(packet.dst_port)
        size = cls._size_bucket(packet.size or 0)
        src_flags = cls._ip_flags(packet.src_ip)
        dst_flags = cls._ip_flags(packet.dst_ip)
        return proto + src_ports + dst_ports + size + src_flags + dst_flags

    @staticmethod
    def _sigmoid(value: float) -> float:
        try:
            return 1.0 / (1.0 + pow(2.718281828459045, -value))
        except OverflowError:
            return 0.0 if value < 0 else 1.0

    def _ensure_weights(self, dim: int):
        if self.weights is None or len(self.weights) != dim:
            self.weights = [0.0] * dim

    def predict_proba(self, packet) -> float:
        features = self.extract_features(packet)
        self._ensure_weights(len(features))
        score = self.bias + sum(w * x for w, x in zip(self.weights, features))
        return self._sigmoid(score)

    def predict(self, packet, threshold: float = 0.5) -> tuple[str, float]:
        proba = self.predict_proba(packet)
        return ("allow" if proba >= threshold else "block", proba)

    def fit(self,
            packets: List[object],
            labels: List[int],
            epochs: int = 400,
            lr: float = 0.1,
            l2: float = 0.001):
        if not packets:
            raise ValueError("No packet data available for training.")

        X = [self.extract_features(pkt) for pkt in packets]
        self._ensure_weights(len(X[0]))

        for _ in range(epochs):
            gradients = [0.0] * len(self.weights)
            bias_grad = 0.0
            for features, label in zip(X, labels):
                score = self.bias + sum(w * x for w, x in zip(self.weights, features))
                pred = self._sigmoid(score)
                error = pred - label
                bias_grad += error
                for i, x in enumerate(features):
                    gradients[i] += error * x + l2 * self.weights[i]
            n = len(X)
            self.weights = [w - lr * (g / n) for w, g in zip(self.weights, gradients)]
            self.bias -= lr * (bias_grad / n)

    def save(self, path: str) -> None:
        data = {"weights": self.weights, "bias": self.bias}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "AIModel":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(weights=data["weights"], bias=data["bias"])
