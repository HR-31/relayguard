"""Arena: run a detector configuration against the red team and score both sides.

Money, not just flags, is the unit of account. An issuer blocks a token the first time
it is flagged, so for every attack scenario:

    extracted = value of the taps that got through before the first flag
    prevented = 1 - extracted / attempted

A family counts as *robustly covered* when at least 80% of the value its scenarios
attempted was prevented. Benign quality is tracked separately (false-positive rate and
precision); a genuine tap flagged within 24 h of an undetected attack on the same
token is counted as "collateral", not as a false positive, because the alert is
pointing at a real compromise.
"""
from __future__ import annotations

import random
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Union

from .adversary import DAY, FAMILIES, FAMILY_ORDER, World
from .layered import LayeredDetector

ROBUST = 0.80
Plan = Dict[str, Union[int, List[Dict[str, Any]]]]


def default_plan(n: int = 25) -> Plan:
    return {f: n for f in FAMILY_ORDER}


def _agg() -> Dict[str, Any]:
    return {"n": 0, "attempted": 0.0, "extracted": 0.0, "detected": 0}


def _close(a: Dict[str, Any]) -> Dict[str, Any]:
    a["prevented"] = 1.0 - a["extracted"] / a["attempted"] if a["attempted"] else 1.0
    a["detect_rate"] = a["detected"] / a["n"] if a["n"] else 0.0
    return a


def run(layers: Iterable[str], params: Optional[Dict[str, float]] = None, seed: int = 1,
        plan: Optional[Plan] = None, n_tokens: int = 480,
        keep_scenarios: bool = False) -> Dict[str, Any]:
    plan = plan if plan is not None else default_plan()
    world = World(seed=seed, n_tokens=n_tokens)
    rng = random.Random(seed * 7919 + 13)
    meta: Dict[int, Dict[str, Any]] = {}
    sid = 0
    for fam in FAMILY_ORDER:
        if fam not in plan:
            continue
        spec = plan[fam]
        genomes = spec if isinstance(spec, list) else [FAMILIES[fam]["typical"](rng) for _ in range(spec)]
        for g in genomes:
            sid += 1
            rows = FAMILIES[fam]["build"](world, rng, sid, g)
            meta[sid] = {"family": fam, "genome": g, "valid": bool(rows), "taps": len(rows),
                         "attempted": sum(x["amount"] for x in rows), "extracted": 0.0,
                         "detected": False, "provider": rows[0]["provider"] if rows else None}
            world.attack_rows.extend(rows)

    det = LayeredDetector(enabled=layers, params=params)
    blocked: set = set()
    evaded_at: Dict[str, int] = {}
    n_benign = fp = collateral = tp = attack_taps = 0
    fp_reasons: Counter = Counter()
    layer_hits: Counter = Counter()

    for tx in world.finalize():
        tok = tx["token"]
        if tx["is_relay"]:
            if tok in blocked:
                continue                       # token already blocked: declined upstream
            attack_taps += 1
            res = det.score(tx)
            m = meta[tx["scn"]]
            if res.verdict == "RELAY":
                blocked.add(tok)
                m["detected"] = True
                tp += 1
                for s in res.signals:
                    layer_hits[s.name] += 1
            else:
                m["extracted"] += tx["amount"]
                evaded_at[tok] = tx["timestamp"]
            continue
        if tx["timestamp"] < world.t_eval:
            det.score(tx, learn=True)          # clean history: learn baselines, no blocking
            continue
        res = det.score(tx)
        n_benign += 1
        if res.verdict == "RELAY":
            if tok in evaded_at and tx["timestamp"] - evaded_at[tok] < DAY:
                collateral += 1
            else:
                fp += 1
                fp_reasons["+".join(sorted(s.name for s in res.signals))] += 1

    fams: Dict[str, Dict[str, Any]] = {}
    provs: Dict[str, Dict[str, Any]] = {}
    total = _agg()
    for m in meta.values():
        if not m["valid"]:
            continue
        for bucket in (fams.setdefault(m["family"], _agg()),
                       provs.setdefault(m["provider"], _agg()), total):
            bucket["n"] += 1
            bucket["attempted"] += m["attempted"]
            bucket["extracted"] += m["extracted"]
            bucket["detected"] += 1 if m["detected"] else 0
    for b in list(fams.values()) + list(provs.values()) + [total]:
        _close(b)

    out = {
        "families": fams, "providers": provs,
        "robust": [f for f in FAMILY_ORDER if f in fams and fams[f]["prevented"] >= ROBUST],
        "attempted": total["attempted"], "extracted": total["extracted"],
        "prevented": total["prevented"], "scenarios": total["n"],
        "n_benign": n_benign, "fp": fp, "collateral": collateral,
        "fpr": fp / n_benign if n_benign else 0.0,
        "tp": tp, "attack_taps": attack_taps,
        "precision": tp / (tp + fp) if (tp + fp) else 1.0,
        "fp_reasons": dict(fp_reasons.most_common(8)),
        "layer_hits": dict(layer_hits.most_common()),
    }
    if keep_scenarios:
        out["scenario_detail"] = meta
    return out


def average(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pool several seeds into one result (sums, then re-derives the ratios)."""
    fams: Dict[str, Dict[str, Any]] = {}
    provs: Dict[str, Dict[str, Any]] = {}
    tot = {k: 0.0 for k in ("attempted", "extracted", "n_benign", "fp", "collateral", "tp",
                            "attack_taps", "scenarios")}
    for r in results:
        for k in tot:
            tot[k] += r[k]
        for src, dst in ((r["families"], fams), (r["providers"], provs)):
            for name, a in src.items():
                b = dst.setdefault(name, _agg())
                for k in ("n", "attempted", "extracted", "detected"):
                    b[k] += a[k]
    for b in list(fams.values()) + list(provs.values()):
        _close(b)
    return {
        "families": fams, "providers": provs,
        "robust": [f for f in FAMILY_ORDER if f in fams and fams[f]["prevented"] >= ROBUST],
        "attempted": tot["attempted"], "extracted": tot["extracted"],
        "prevented": 1.0 - tot["extracted"] / tot["attempted"] if tot["attempted"] else 1.0,
        "scenarios": int(tot["scenarios"]), "n_benign": int(tot["n_benign"]),
        "fp": int(tot["fp"]), "collateral": int(tot["collateral"]),
        "fpr": tot["fp"] / tot["n_benign"] if tot["n_benign"] else 0.0,
        "tp": int(tot["tp"]), "attack_taps": int(tot["attack_taps"]),
        "precision": tot["tp"] / (tot["tp"] + tot["fp"]) if (tot["tp"] + tot["fp"]) else 1.0,
    }
