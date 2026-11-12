"""RelayGuard — an issuer-side detector for NFC contactless relay ("Ghost Tap") fraud.

Defensive security only. This package scores authorization-stream transactions for
relay signatures (latency, impossible travel, no-PIN at unseen terminals, velocity).
It contains no attack code.
"""

from .detector import RelayDetector, ScoreResult, Signal, FLAG_THRESHOLD

__all__ = ["RelayDetector", "ScoreResult", "Signal", "FLAG_THRESHOLD"]
__version__ = "0.1.0"
