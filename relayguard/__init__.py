"""RelayGuard — an issuer-side detector for NFC contactless relay ("Ghost Tap") fraud.

Defensive security only. This package scores authorization-stream transactions for
relay signatures (latency, impossible travel, no-PIN at unseen terminals, velocity).
It contains no attack code.
"""

from .detector import RelayDetector, ScoreResult, Signal, FLAG_THRESHOLD
from .layered import LayeredDetector

__all__ = ["RelayDetector", "LayeredDetector", "ScoreResult", "Signal", "FLAG_THRESHOLD"]
__version__ = "0.2.0"
