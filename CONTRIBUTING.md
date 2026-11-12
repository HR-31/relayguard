# Contributing to RelayGuard

RelayGuard is in active development (alpha) and contributions are welcome.

## Ground rules

- **Defensive only.** This project detects relay fraud. It must never contain working
  attack code, relay tooling, or anything designed to defeat a payment system.
- Keep the core (`relayguard/`) dependency-free (Python standard library).
- Add or update a test for any behaviour change: `python -m unittest -v tests.test_detector`.
- Run the eval harness and include before/after metrics in your PR description:
  `python -m relayguard.evaluate`.

## Development

```bash
git clone https://github.com/HR-31/relayguard
cd relayguard
python -m unittest -v tests.test_detector   # tests
python -m relayguard.evaluate               # metrics
python serve.py                             # live demo at http://127.0.0.1:8723/
```

## Good first issues

- Additional relay signals (e.g. terminal-country risk, device-attestation gaps).
- A pluggable threshold / weight config instead of module constants.
- An ISO 8583 / ISO 20022 adapter so the detector can read a real auth feed.
- Replace the synthetic simulator with a loader for public labelled fraud datasets.
