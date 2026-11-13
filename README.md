# RelayGuard

![CI](https://github.com/HR-31/relayguard/actions/workflows/ci.yml/badge.svg)
![status](https://img.shields.io/badge/status-alpha%20·%20in%20development-orange)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

**An issuer-side detector for NFC contactless relay ("Ghost Tap") fraud.**

> 🚧 **Status: in active development (alpha).** Signals, weights and the data model
> will change. This is a reference implementation, **not production-ready** — do not
> run it against live authorization traffic. Issues and contributions are welcome.

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

## Two detectors

- **`RelayDetector`** (`detector.py`) — the original five-signal detector: latency,
  impossible travel, no-PIN at a new terminal, velocity burst, distance from home. It
  powers the live demo and is the easiest thing to read.
- **`LayeredDetector`** (`layered.py`) — the hardened, defence-in-depth detector that an
  adversarial loop evolved from those five signals into **30 layers across 25
  independent evidence groups**, covering six card-network / wallet providers. Build it
  with `LayeredDetector.full()`.

A transaction scoring **≥ 50** is flagged `RELAY`. Signals are additive (strongest per
evidence group, so correlated signals never double-count) and capped at 100. Both
detectors are **stateful and streaming**, keep per-token and per-terminal history, and
deliberately do *not* cascade a flagged relay into false positives on the cardholder's
genuine next tap.

## Hardened through adversarial co-evolution

`coevolve.py` runs a red-team / blue-team loop: the red team attacks, the blue team
patches the costliest hole, and it repeats — locking every fix in with a test. Headline
result (regenerate with `python3 -m relayguard.coevolve`; full figures in
[`ADVERSARIAL_REPORT.md`](ADVERSARIAL_REPORT.md), visual version in
`reports/coevolution.html`):

| Measure | First release | After the loop |
|---|---|---|
| Attack families robustly covered | 2 of 15 | **15 of 15** |
| Fraud value blocked (benchmark, unseen seeds) | ~5% | **100%** |
| Best attack the automated red team can still find | ~£12,000 | **£0** (observable-latency relay) |
| Detection layers | 5 | **30** |
| Provider profiles with their own rules | none | **6** |
| False-positive rate on genuine taps | 0.0% | **~0.3%** |

The loop runs in three phases: a **technique ladder** (patch the worst family, repeat);
an **automated red team** that fuzzes each attack's full parameter space and deploys the
patch removing the most value within a false-positive budget; and an honest
**assumption attack** — the red team is handed a latency-masking relay, so only
latency-*independent* layers can help. The residual under that hardest case is reported,
not hidden.

## Regression locks — every gap stays closed

A hole is only closed once a test fails if it reopens. `gaps.py` freezes the hardest
attack the red team found for each family, at both an observable and a latency-masked
relay floor, with a locked ceiling on the value the detector may ever let through. The
fixture ([`tests/fixtures/locked_gaps.json`](tests/fixtures/locked_gaps.json)) only ever
tightens — each loop teaches it one more attack it must never again permit.

```bash
python3 -m relayguard.gaps --freeze   # extend the locks after a loop
python3 -m relayguard.gaps --check    # what the regression test enforces
```

## Realistic-world cross-check

To avoid grading its own homework, the detector is also run against the
[Fraud-Detection-Handbook](https://fraud-detection-handbook.github.io/) simulator
(faithfully reimplemented in `realworld.py`) — an independently-designed fraud model
whose fraud is *not* relay. The honest findings: a **~0.02% false-positive rate** on a
world it was never tuned on (it doesn't misfire on an unfamiliar population), and **low
recall by design** (it detects relay, not generic card fraud). It surfaces one real
limitation — skimmed-terminal fraud is near-uncatchable from transaction features alone
and needs issuer *fraud-feedback*. That gap is documented, not hidden.

## Run it

Requires only Python 3 (standard library — no pip install).

```bash
python3 -m relayguard.evaluate     # original detector: confusion matrix + metrics
python3 -m relayguard.coevolve     # the full red/blue loop -> ADVERSARIAL_REPORT.md (~4 min)
python3 -m relayguard.report_html  # render reports/coevolution.html (visual dashboard)
python3 -m relayguard.realworld    # cross-check against the independent fraud model
python3 -m relayguard.gaps --check # replay every locked gap
python3 -m unittest -v             # the whole test suite
python3 serve.py                   # live browser demo at http://127.0.0.1:8723/
```

The live demo replays the stream through the server's `/api/score` endpoint, so what you
see on screen is the actual detector verdict — not a client-side reimplementation.

## Layout

```
relayguard/
  detector.py     # original five-signal streaming detector (powers the demo)
  layered.py      # the evolved 30-layer LayeredDetector
  providers.py    # six card-network / wallet provider profiles
  simulator.py    # synthetic labelled stream (original detector)
  adversary.py    # the red team: a synthetic world + 15 attack families
  arena.py        # scores a detector config against the red team (money, not just flags)
  redteam.py      # automated fuzzer: searches each attack's parameter space
  coevolve.py     # the red/blue co-evolution loop + report
  gaps.py         # freeze/check the accumulating regression locks
  realworld.py    # the Fraud-Detection-Handbook benchmark + a real-feed adapter
  evaluate.py / report_html.py
serve.py, static/ # live dashboard
tests/            # unit, end-to-end, regression-lock and cross-world tests
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

## Maintainer

Built and maintained by **Harish Ravi** — co-founder of
[SimplyDiscover](https://simply-discover.com), which is my current focus. RelayGuard
is an independent open-source project; contributions and issues are welcome.

## License

MIT — see [LICENSE](LICENSE).
