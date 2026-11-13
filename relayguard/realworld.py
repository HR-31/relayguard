"""A realistic, independently-designed benchmark — and an adapter for real feeds.

RelayGuard's own world (adversary.py) is built around relay fraud, so testing the
detector only against it risks grading our own homework. This module runs the detector
against the **Fraud-Detection-Handbook** transaction simulator (Le Borgne, Siblini,
Lebichot & Bontempi, *Reproducible Machine Learning for Credit Card Fraud Detection*),
a widely-used, independently-designed model whose fraud has nothing to do with relay:

  * Scenario 1 — any transaction over 220 is fraud (a stolen-card spending spree).
  * Scenario 2 — two terminals per day are "compromised"; every tap on them is fraud
                 for 28 days (a skimmed POS). The transactions look completely normal.
  * Scenario 3 — three customers per day are "compromised"; a third of their taps over
                 the next 14 days have their amount multiplied by 5 (account takeover).

This is a genuine out-of-distribution test. The honest expectation: the detector
should catch the amount-driven scenarios (1 and 3) through its spend layers, and will
*miss* scenario 2 — normal-looking taps on a skimmed terminal carry no signal unless
the issuer feeds back which terminals are known-bad. That gap is real and is recorded,
not hidden (see `tests/test_realworld.py` and ADVERSARIAL_REPORT.md).

The simulator is reimplemented here in the standard library (the original uses numpy);
the algorithm and constants follow the Handbook's Chapter 3 §2. `adapt()` maps any
simulator/CSV rows onto the detector's feature schema, so a real authorization feed can
be scored the same way.
"""
from __future__ import annotations

import math
import random
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .arena import DAY
from .layered import LayeredDetector
from .providers import ALL_PROVIDER_KEYS, PROVIDERS

T0 = 1_794_000_000
GRID = 100.0
KM_PER_UNIT = 3.0             # 100-unit grid -> ~300 km across
LONDON = (51.5074, -0.1278)


def _grid_to_latlon(x: float, y: float) -> Tuple[float, float]:
    lat = LONDON[0] + (y - 50.0) * KM_PER_UNIT / 111.0
    lon = LONDON[1] + (x - 50.0) * KM_PER_UNIT / (111.0 * math.cos(math.radians(LONDON[0])))
    return lat, lon


# ---------------------------------------------------------------- the simulator
def _customers(n: int, rng: random.Random) -> List[Dict[str, Any]]:
    out = []
    for cid in range(n):
        x, y = rng.uniform(0, GRID), rng.uniform(0, GRID)
        mean_amount = rng.uniform(5, 100)
        out.append({"CUSTOMER_ID": cid, "x": x, "y": y, "mean_amount": mean_amount,
                    "std_amount": mean_amount / 2, "mean_nb_tx_per_day": rng.uniform(0, 4)})
    return out


def _terminals(n: int, rng: random.Random) -> List[Dict[str, Any]]:
    return [{"TERMINAL_ID": tid, "x": rng.uniform(0, GRID), "y": rng.uniform(0, GRID)}
            for tid in range(n)]


def _within_radius(cust: Dict[str, Any], terms: List[Dict[str, Any]], r: float) -> List[int]:
    return [t["TERMINAL_ID"] for t in terms
            if math.hypot(t["x"] - cust["x"], t["y"] - cust["y"]) < r]


def _poisson(lam: float, rng: random.Random) -> int:
    if lam <= 0:
        return 0
    el, k, p = math.exp(-lam), 0, 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= el:
            return k - 1


def _gauss_amount(mean: float, std: float, rng: random.Random) -> float:
    a = rng.gauss(mean, std)
    if a < 0:
        a = rng.uniform(0, mean * 2)
    return round(a, 2)


def simulate(n_customers: int = 900, n_terminals: int = 2200, nb_days: int = 45,
             radius: float = 5.0, seed: int = 0) -> List[Dict[str, Any]]:
    """Faithful stdlib port of the Handbook simulator. Returns labelled raw rows."""
    rng_c = random.Random(seed)
    rng_t = random.Random(seed + 1)
    customers = _customers(n_customers, rng_c)
    terminals = _terminals(n_terminals, rng_t)
    for c in customers:
        c["available_terminals"] = _within_radius(c, terminals, radius)

    rows: List[Dict[str, Any]] = []
    for c in customers:
        if not c["available_terminals"]:
            continue
        rc = random.Random(c["CUSTOMER_ID"])
        for day in range(nb_days):
            nb = _poisson(c["mean_nb_tx_per_day"], rc)
            for _ in range(nb):
                t = int(rc.gauss(DAY / 2, 20000))
                if not (0 < t < DAY):
                    continue
                amt = _gauss_amount(c["mean_amount"], c["std_amount"], rc)
                tid = rc.choice(c["available_terminals"])
                rows.append({"CUSTOMER_ID": c["CUSTOMER_ID"], "TERMINAL_ID": tid,
                             "TX_AMOUNT": amt, "TX_TIME_SECONDS": t + day * DAY,
                             "TX_TIME_DAYS": day, "TX_FRAUD": 0, "TX_FRAUD_SCENARIO": 0})

    rows.sort(key=lambda r: r["TX_TIME_SECONDS"])
    _add_frauds(rows, customers, terminals, nb_days)
    cust_xy = {c["CUSTOMER_ID"]: (c["x"], c["y"]) for c in customers}
    term_xy = {t["TERMINAL_ID"]: (t["x"], t["y"]) for t in terminals}
    for r in rows:
        r["_cust_xy"], r["_term_xy"] = cust_xy[r["CUSTOMER_ID"]], term_xy[r["TERMINAL_ID"]]
    return rows


def _add_frauds(rows: List[Dict[str, Any]], customers, terminals, nb_days: int) -> None:
    all_terms = [t["TERMINAL_ID"] for t in terminals]
    all_custs = [c["CUSTOMER_ID"] for c in customers]
    by_day: Dict[int, List[Dict[str, Any]]] = {}
    for r in rows:
        by_day.setdefault(r["TX_TIME_DAYS"], []).append(r)

    for r in rows:                                   # scenario 1
        if r["TX_AMOUNT"] > 220:
            r["TX_FRAUD"], r["TX_FRAUD_SCENARIO"] = 1, 1

    for day in range(nb_days):                       # scenario 2: compromised terminals, 28d
        comp = set(random.Random(day).sample(all_terms, min(2, len(all_terms))))
        for d in range(day, min(day + 28, nb_days)):
            for r in by_day.get(d, ()):
                if r["TERMINAL_ID"] in comp:
                    r["TX_FRAUD"], r["TX_FRAUD_SCENARIO"] = 1, 2

    for day in range(nb_days):                       # scenario 3: compromised customers, 14d
        comp = set(random.Random(day + 7).sample(all_custs, min(3, len(all_custs))))
        window = [r for d in range(day, min(day + 14, nb_days)) for r in by_day.get(d, ())
                  if r["CUSTOMER_ID"] in comp]
        if not window:
            continue
        rs = random.Random(day)
        for r in rs.sample(window, k=int(len(window) / 3)):
            r["TX_AMOUNT"] = round(r["TX_AMOUNT"] * 5, 2)
            r["TX_FRAUD"], r["TX_FRAUD_SCENARIO"] = 1, 3


# ------------------------------------------------------------------- the adapter
def adapt(rows: Iterable[Dict[str, Any]], *, base_ts: int = T0,
          provider_of: Optional[Callable[[Any], str]] = None) -> List[Dict[str, Any]]:
    """Map simulator rows onto the detector's feature schema.

    Latency is synthesised as a normal local tap for every row — the Handbook's fraud is
    card-present/account-takeover, not relay, so none of it carries relay latency. This
    is deliberate: it measures what the detector catches WITHOUT its headline signal.
    """
    def _prov(cid: Any) -> str:
        return ALL_PROVIDER_KEYS[hash(("p", cid)) % len(ALL_PROVIDER_KEYS)]

    provider_of = provider_of or _prov
    out: List[Dict[str, Any]] = []
    jitter = random.Random(12345)
    for r in rows:
        cid, tid = r["CUSTOMER_ID"], r["TERMINAL_ID"]
        prov = PROVIDERS[provider_of(cid)]
        tlat, tlon = _grid_to_latlon(*r["_term_xy"])
        clat, clon = _grid_to_latlon(*r["_cust_xy"])
        amount = float(r["TX_AMOUNT"])
        out.append({
            "id": f"rw{r.get('TX_TIME_SECONDS', 0)}-{cid}-{tid}",
            "token": f"C{cid}", "provider": prov.key, "amount": amount,
            "terminal_id": f"T{tid}", "city": "sim", "country": "GB", "home_country": "GB",
            "lat": tlat, "lon": tlon, "enroll_lat": clat, "enroll_lon": clon,
            "timestamp": base_ts + int(r["TX_TIME_SECONDS"]),
            "apdu_latency_ms": max(12, int(jitter.gauss(46, 14))),
            "cdcvm_claimed": prov.is_wallet and amount > prov.contactless_limit,
            "token_age_s": 500 * DAY, "expiry_ym": 202809, "aid": prov.aid_prefix,
            "pan_brand": prov.brand, "atc": 0, "mcc": "retail", "transit_entitlement": False,
            "is_fraud": bool(r.get("TX_FRAUD", 0)), "scenario": r.get("TX_FRAUD_SCENARIO", 0),
        })
    out.sort(key=lambda x: x["timestamp"])
    counter: Dict[str, int] = {}
    for x in out:
        counter[x["token"]] = counter.get(x["token"], 10) + 1
        x["atc"] = counter[x["token"]]
    return out


# ---------------------------------------------------------------- evaluation
def evaluate(rows: List[Dict[str, Any]], detector: Optional[LayeredDetector] = None,
             warmup_days: int = 7) -> Dict[str, Any]:
    """Per-transaction scoring, to compare like-for-like with the Handbook's own labels
    (which are per transaction, no card-blocking). Also reports the issuer-blocking view
    (once a token is flagged its later taps are declined) for context.
    """
    det = detector or LayeredDetector.full()
    warmup = T0 + warmup_days * DAY
    by_scn = {1: [0, 0], 2: [0, 0], 3: [0, 0]}       # scenario -> [caught, total]
    tp = fp = tn = fn = 0
    first_flag_fp = 0                                 # distinct legit tokens wrongly flagged
    seen_fp_tok: set = set()
    blocked: set = set()                             # issuer-blocking view
    blk_fraud_caught = blk_fraud_total = blk_legit_declined = legit_total = 0
    for tx in rows:
        tok = tx["token"]
        pre = tok in blocked
        res = det.score(tx)
        flagged = res.verdict == "RELAY"
        if flagged:
            blocked.add(tok)
        if tx["timestamp"] < warmup:
            continue
        # --- per-transaction view (primary) ---
        if tx["is_fraud"]:
            sc = tx["scenario"]
            if sc in by_scn:
                by_scn[sc][1] += 1
                by_scn[sc][0] += 1 if flagged else 0
            tp += 1 if flagged else 0
            fn += 0 if flagged else 1
        else:
            if flagged:
                fp += 1
                if tok not in seen_fp_tok:
                    seen_fp_tok.add(tok)
                    first_flag_fp += 1
            else:
                tn += 1
        # --- issuer-blocking view (secondary) ---
        if tx["is_fraud"]:
            blk_fraud_total += 1
            blk_fraud_caught += 1 if (flagged or pre) else 0
        else:
            legit_total += 1
            blk_legit_declined += 1 if (flagged or pre) else 0
    n = tp + fp + tn + fn
    return {
        "n": n, "fraud": tp + fn, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "precision": tp / (tp + fp) if (tp + fp) else 1.0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "first_flag_fpr": first_flag_fp / (tn + fp) if (tn + fp) else 0.0,
        "by_scenario": {s: {"recall": (c / t if t else 0.0), "n": t} for s, (c, t) in by_scn.items()},
        "issuer_blocking": {
            "fraud_recall": blk_fraud_caught / blk_fraud_total if blk_fraud_total else 0.0,
            "legit_decline_rate": blk_legit_declined / legit_total if legit_total else 0.0,
        },
    }


def run(seed: int = 0, **kw) -> Dict[str, Any]:
    rows = adapt(simulate(seed=seed, **kw))
    return {"rows": len(rows), **evaluate(rows)}


if __name__ == "__main__":
    import json
    r = run()
    print(json.dumps({k: v for k, v in r.items() if k != "rows"}, indent=1))
    print(f"rows={r['rows']}")
