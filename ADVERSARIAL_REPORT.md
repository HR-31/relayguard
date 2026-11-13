# Adversarial co-evolution report

_Generated 2026-11-13 by `python3 -m relayguard.coevolve` (234 s). Every number below comes from the bundled synthetic world; none of it is a claim about real authorization data._

## Result

| Measure | First release | After the loop | Change |
|---|---|---|---|
| Attack families robustly covered (≥80% of attempted value blocked) | 2 of 15 | 15 of 15 | 7.5× |
| Attempted fraud value blocked — benchmark, unseen seeds | 4.6% | 100.0% | 21.7× |
| Fraud value leaking — fuzzed attack space | 65.0% | 0.0% | eliminated |
| Best attack the red team could find (per scenario) | £12,038 | £0 | eliminated |
| Detection layers | 5 | 30 | 6.0× |
| Independent evidence groups | 5 | 25 | 5.0× |
| Provider profiles with their own rules | none | 6 | — |
| False-positive rate on genuine taps | 0.00% | 0.27% | the cost |
| Precision of a flag | 100.0% | 96.9% | |

Benchmark figures are pooled over seeds [11, 23, 37], which the loop never tuned against (25 scenarios per family per seed). The fuzzed rows hold under the stated assumption that a relayed tap cannot get below 95 ms — see *Sensitivity* for what happens when it can.

## How the loop ran

### Phase 1 — technique ladder

Each round the red team runs every family, the family extracting the most money is picked, and the blue playbook's counter-measures for it are deployed.

| Round | Red team's best technique | Took | Blue deployed | Blocked after | Families covered | FPR |
|---|---|---|---|---|---|---|
| 1 | Token churn | £26,789 | `latency_jump`, `terminal_fresh_burst` | 87.7% | 4 of 15 | 0.01% |
| 2 | Low-and-slow drain | £24,509 | `sustained_velocity`, `anomalous_spend_accumulation` | 89.7% | 8 of 15 | 0.03% |
| 3 | Express-transit abuse | £20,407 | `transit_misuse` | 100.0% | 9 of 15 | 0.03% |
| 4 | Card-brand mix-up | £14,451 | `aid_brand_mismatch` | 100.0% | 10 of 15 | 0.03% |
| 5 | CVM / PIN-bypass tamper | £14,256 | `cvm_integrity` | 100.0% | 11 of 15 | 0.03% |
| 6 | Seasoned token | £12,446 | `chronic_latency`, `spend_spike` | 88.1% | 12 of 15 | 0.03% |
| 7 | Plausible-travel relay | £2,528 | `new_country` | 94.6% | 13 of 15 | 0.04% |
| 8 | Cryptogram replay / pre-play | £2,144 | `atc_regression` | 100.0% | 14 of 15 | 0.04% |
| 9 | Expired card revived ("Zombie Card") | £2,039 | `expired_card` | 100.0% | 15 of 15 | 0.04% |

### Phase 2 — automated red team

The fuzzer searches each family's full parameter space. The blue side trials every remaining patch against the red team's best attacks and deploys the one that removes the most value, rejecting any that would push false positives above 0.5%.

Start: 2.9% of fuzzed value leaking, best attack £4,484. End: 0.0% leaking, best attack £0.

| # | What the red team found | Worth | Patch deployed | Red team's best attacks, before → after | Leak after |
|---|---|---|---|---|---|
| 1 | **Low-and-slow drain** — 95 ms, £263/tap, 17 taps every 3min, 49min after last genuine tap, 598 km away | £4,484 | `tighten_latency_margin` — Relative-latency margin 55 → 40 ms, closing the band between the relay floor and the threshold. | £9,311 → £634 | 1.1% |
| 2 | **Token churn** — 132 ms, £84/tap, 16 tokens, every 20min, token 8.8d old, 59 km away | £1,343 | `anomalous_new_terminal` — Relay-like latency at a terminal the token has never used is enough on its own. | £2,209 → £0 | 0.0% |

### Phase 3 — latency-masking relay (50 ms floor)

The red team is handed a relay that timing alone cannot distinguish from a local tap. Only latency-independent counter-measures can help.

Start: 42.6% of fuzzed value leaking, best attack £8,318. End: 14.7% leaking, best attack £6,098.

| # | What the red team found | Worth | Patch deployed | Red team's best attacks, before → after | Leak after |
|---|---|---|---|---|---|
| 1 | **Low-and-slow drain** — 63 ms, £561/tap, 18 taps every 13.5h, 21min after last genuine tap, 5 km away | £8,318 | `captive_terminal` — Token and terminal that have only ever dealt with each other, then a high-value tap. | £29,583 → £23,791 | 40.9% |
| 2 | **Token churn** — 62 ms, £489/tap, 20 tokens, every 13min, token 4.3d old, 5 km away | £9,826 | `young_merchant_accumulation` — Repeated high-value spend at merchants that only just appeared. | £29,658 → £18,719 | 34.8% |
| 3 | **Token churn** — 69 ms, £593/tap, 20 tokens, every 50min, token 51min old, 46 km away | £11,872 | `churn_window_24h` — Look back 24 h (not 30 min) for other fresh tokens at the same terminal. | £24,344 → £13,099 | 34.1% |
| 4 | **Token churn** — 81 ms, £505/tap, 18 tokens, every 58s, token 12.9d old, 452 km away | £9,103 | `dormant_token_first_use` — A wallet that sat unused since provisioning and opens with a high-value no-PIN tap. | £21,906 → £12,772 | 24.5% |
| 5 | **Token churn** — 80 ms, £370/tap, 15 tokens, every 5.8h, token 7.5h old, 23 km away | £5,533 | `stranger_merchant_highvalue` — High value + just-appeared merchant + a place the token has never been, together. | £19,376 → £18,375 | 23.5% |
| 6 | **Token churn** — 78 ms, £389/tap, 17 tokens, every 33s, token 30.0d old, 493 km away | £6,610 | `displaced_new_token` — A new or never-used wallet first tapped far from the cardholder's home. | £16,171 → £15,268 | 15.9% |
| 7 | **Low-and-slow drain** — 83 ms, £600/tap, 16 taps every 42min, 1.1h after last genuine tap, 76 km away | £4,759 | `unused_token_burst` — Never-used tokens count toward a terminal burst, not only freshly provisioned ones. | £18,109 → £15,253 | 14.0% |
| 8 | **Low-and-slow drain** — 58 ms, £453/tap, 15 taps every 53min, 16.2h after last genuine tap, 458 km away | £4,497 | `strong_fresh_burst` — Three or more fresh tokens at one terminal is decisive without any latency evidence. | £15,309 → £13,431 | 14.7% |

## Coverage by attack family

| Family | Type | First release | After the loop | Still leaks to a tuned attacker |
|---|---|---|---|---|
| Express-transit abuse | protocol | 0.0% | 100.0% | n/a (binary check) |
| Card-brand mix-up | protocol | 0.0% | 100.0% | n/a (binary check) |
| CVM / PIN-bypass tamper | protocol | 0.0% | 100.0% | n/a (binary check) |
| Expired card revived ("Zombie Card") | protocol | 0.0% | 100.0% | n/a (binary check) |
| Cryptogram replay / pre-play | protocol | 0.0% | 100.0% | n/a (binary check) |
| Latency-shaped relay | relay | 0.0% | 100.0% | £0 |
| Relay with phished PIN | relay | 0.0% | 100.0% | £0 |
| ATM cash-out relay | relay | 0.0% | 100.0% | £0 |
| Classic ghost tap | relay | 100.0% | 100.0% | £0 |
| Stealth domestic relay | relay | 87.6% | 100.0% | £0 |
| Low-and-slow drain | relay | 0.0% | 100.0% | £0 |
| Plausible-travel relay | relay | 0.0% | 100.0% | £0 |
| Fresh-wallet cash-out | relay | 0.0% | 100.0% | £0 |
| Token churn | relay | 0.0% | 100.0% | £0 |
| Seasoned token | relay | 0.0% | 100.0% | £0 |

## Coverage by provider

| Provider | First release | After the loop |
|---|---|---|
| Visa (card) | 0.0% | 100.0% |
| Mastercard (card) | 0.0% | 100.0% |
| American Express | 0.0% | 100.0% |
| Google Pay | 9.8% | 100.0% |
| Apple Pay | 4.8% | 100.0% |
| ATM / EFTPOS | 0.0% | 100.0% |

## Sensitivity: what if relay latency can be hidden?

Most relay coverage depends on a relayed tap being measurably slower than a local one. This table re-runs the benchmark and the fuzzer while lowering the latency floor the red team is allowed, with the fuzzer restricted to a competent attacker who stays within 50 ms of that floor. It is the honest measure of depth: what survives when the main signal is gone.

| Relay floor | First release | After phase 2 | After phase 3 (final) |
|---|---|---|---|
| 95 ms | 4.8% blocked · 92.5% leak · best £10,110 | 100.0% blocked · 0.0% leak · best £0 | 100.0% blocked · 0.0% leak · best £0 |
| 80 ms | 4.8% blocked · 92.5% leak · best £10,110 | 98.8% blocked · 7.8% leak · best £6,286 | 99.8% blocked · 0.5% leak · best £358 |
| 65 ms | 4.8% blocked · 92.5% leak · best £10,110 | 82.5% blocked · 27.2% leak · best £6,353 | 92.8% blocked · 1.6% leak · best £1,047 |
| 50 ms | 4.8% blocked · 92.5% leak · best £10,110 | 60.9% blocked · 49.5% leak · best £10,124 | 82.6% blocked · 3.1% leak · best £828 |

## Realistic-world cross-check

To avoid grading our own homework, the shipped detector is also run against the [Fraud-Detection-Handbook](https://fraud-detection-handbook.github.io/) transaction simulator — an independently-designed model whose fraud is **not** relay: a flat over-220 rule (scenario 1), skimmed terminals (scenario 2), and account-takeover amount inflation (scenario 3).

- **False-positive rate: 0.024%** per transaction on 154,499 transactions from a world it was never tuned on — the detector does not misfire on an unfamiliar but legitimate population.
- **Recall: 0.5%** — low *by design*. RelayGuard detects relay, not generic card fraud; the two threat models barely overlap.

| Handbook fraud scenario | What it is | RelayGuard recall |
|---|---|---|
| Scenario 1 | Flat over-£220 rule | 0.0% |
| Scenario 2 | Skimmed / compromised terminal | 0.0% |
| Scenario 3 | Account-takeover amount inflation (×5) | 1.1% |

The honest limitation this surfaces: **scenario 2 is near-uncatchable from transaction features alone** — a normal-looking tap on a skimmed terminal carries no signal. Catching it needs issuer *fraud-feedback* (mark a terminal risky once confirmed-fraud taps appear on it), which this detector does not yet consume. That is the next layer to build, and it is recorded here rather than hidden.

## Final configuration

- **Layers (30):** `latency_tier`, `geo_travel`, `nopin_new_terminal`, `velocity_burst`, `far_from_home`, `latency_jump`, `chronic_latency`, `fresh_token_highvalue`, `fresh_latency_combo`, `spend_spike`, `terminal_fresh_burst`, `young_terminal`, `expired_card`, `aid_brand_mismatch`, `cvm_integrity`, `atc_regression`, `transit_misuse`, `atm_anomaly`, `sustained_velocity`, `anomalous_spend_accumulation`, `new_country`, `anomalous_new_terminal`, `out_of_area`, `displaced_new_token`, `captive_terminal`, `dormant_token_first_use`, `young_merchant_accumulation`, `stranger_merchant_highvalue`, `atm_daily_limit`, `amount_anomaly`
- **Parameter changes from defaults:** `jump_margin_ms=40`, `churn_window_s=86400`, `accum_window_s=604800`, `burst_strong_n=2`, `burst_counts_unused=1`
- **Patches in the order deployed:** `tighten_latency_margin`, `anomalous_new_terminal`, `captive_terminal`, `young_merchant_accumulation`, `churn_window_24h`, `dormant_token_first_use`, `stranger_merchant_highvalue`, `displaced_new_token`, `unused_token_burst`, `strong_fresh_burst`

`LayeredDetector.full()` builds exactly this configuration (every layer the loop deployed, plus the few it did not need this run, with the hardened parameters).

## What this does not show

- **Synthetic world.** Benign behaviour, latency distributions and attack economics are modelled, not measured. Weights and thresholds would need calibrating on real data.
- **Authored counter-measures.** The loop automates the search for holes, their ranking, patch trials and regression gating. A person wrote each counter-measure.
- **One attacker model.** The red team only explores the families and parameters defined in `adversary.py`. An attack outside that space is not tested — for example several victims funnelled through one long-established complicit merchant.
- **Relay-specialised.** The realistic-world cross-check shows it is not a general fraud detector; generic amount fraud and skimmed-terminal fraud need complementary controls.
- **Latency is the load-bearing signal.** See the sensitivity table. The durable fix for relay is distance bounding at the terminal; this detector is a compensating control.
