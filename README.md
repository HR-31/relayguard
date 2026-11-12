# RelayGuard

**An issuer-side detector for NFC contactless relay ("Ghost Tap") fraud.**

Relay / "Ghost Tap" attacks are the one actively-exploited contactless threat today:
a live tap is relayed over the internet to a mule's phone at a distant terminal. The
cryptography is never broken — the attack defeats *proximity*, not crypto. The open
signal that gives it away (per-APDU network latency) is literally timestamped by the
attack tooling itself and then checked by nobody downstream.

RelayGuard is the mirror image of that gap: a small, dependency-free detector that an
**issuer** can run over its existing authorization stream — no terminal changes, no
hardware, no cardholder action — to flag relay transactions in real time.

> Defensive security only. This repo contains **no attack code**. The simulator
> produces synthetic, labelled transactions; the detector only scores them.

## What it detects

Each transaction is scored by composable signals, every one mapped to a documented
relay indicator:

| Signal | Weight | Why it fires |
|---|---|---|
| `extreme_latency` / `high_latency` / `elevated_latency` | 45 / 30 / 15 | Relaying over a network adds measurable round-trip delay |
| `impossible_travel` / `implausible_travel` | 35 / 20 | One token used in two places too far apart, too fast |
| `highvalue_nopin_newterminal` | 18 | CDCVM (no-PIN) claimed + high value + a terminal never seen for this token |
| `velocity_burst` | 15 | One token sprayed across many terminals in minutes |
| `far_from_home` | 10 | Token used far from its enrolled device region |

A transaction scoring **≥ 50** is flagged `RELAY`. Signals are additive and capped at
100. The detector is **stateful and streaming** — it keeps per-token history, and it
deliberately does *not* cascade a flagged relay into false positives on the
cardholder's genuine next tap.

## Results

On the bundled 124-transaction synthetic stream (`seed=7`):

```
recall (detection rate) :  85.7%   (relays caught)
precision               : 100.0%   (flags that were real)
false-positive rate     :   0.0%
accuracy                :  99.2%
ghost_tap : 4 caught, 0 missed
stealth   : 2 caught, 1 missed   (the intentional hard case)
```

The single missed relay is a stealthy domestic one (low value, moderate latency, no
geo jump) — kept missed on purpose so the numbers stay honest rather than tuned.

## Run it

Requires only Python 3 (standard library — no pip install).

```bash
# 1. Prove it: evaluation harness prints the confusion matrix + metrics
python3 -m relayguard.evaluate

# 2. Tests
python3 -m unittest -v tests.test_detector

# 3. Live demo: a browser dashboard that streams the data through the real detector
python3 serve.py           # then open http://127.0.0.1:8723/
```

The dashboard replays the stream through the server's `/api/score` endpoint, so what
you see on screen is the actual detector verdict — not a client-side reimplementation.

## Layout

```
relayguard/
  detector.py     # the streaming scoring engine (the core)
  simulator.py    # synthetic labelled authorization-stream generator
  evaluate.py     # evaluation harness -> metrics
serve.py          # stdlib HTTP server exposing the detector + dashboard
static/index.html # live dashboard UI
tests/            # unit + end-to-end tests
```

## Why this exists

There is a 2,400★ open-source *attack* toolkit for NFC relay and effectively no
open-source *defence* with any traction. The correct terminal-level fix (distance
bounding / EMVCo RRP / L1RP) lives in papers and spec annexes, not deployable code.
RelayGuard targets the other, immediately-deployable layer: issuer-side detection
from data issuers already have. It is a reference implementation, not a product.

## References

- ThreatFabric — *Ghost Tap: New cash-out tactic with NFC Relay* (2024)
- ESET — NGate relay malware (2024–2026); Group-IB — *Ghost Tapped* (2026)
- *Practical EMV Relay Protection*, IEEE S&P 2022 (distance bounding / L1RP)
- *The EMV Standard: Break, Fix, Verify*, ETH Zürich (2020)

## License

MIT — see [LICENSE](LICENSE).
