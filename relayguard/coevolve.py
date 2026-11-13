"""Adversarial co-evolution loop: red team attacks, blue team patches, repeat.

    python3 -m relayguard.coevolve            # full run (~4 min), writes the report
    python3 -m relayguard.coevolve --quick    # smoke run for CI

Phase 1 — technique ladder
    Start from the five-layer detector that first shipped. Run every attack family.
    Take the family extracting the most money, deploy the counter-measures the blue
    playbook holds for it, re-measure, repeat until every family is robustly covered.

Phase 2 — automated red team
    A fuzzer searches each family's full parameter space for what still gets through
    and how much it is worth. The blue side trials every remaining patch against the
    red team's best attacks, deploys the one that removes the most value without
    breaking the false-positive budget, and the fuzzer goes again.

Phase 3 — attack the assumption
    The relay coverage above leans on relay latency being observable. Phase 3 hands
    the red team a latency-masking relay (a much lower floor) and repeats phase 2 with
    latency-independent counter-measures.

What is automated: the red-team search, ranking holes by value, trialling patches,
regression and false-positive gating. What is authored: the counter-measures themselves.
All numbers come from the bundled synthetic world (adversary.py) and say nothing about
performance on real authorization data.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any, Callable, Dict, List, Optional

from . import arena, realworld, redteam
from .adversary import (DAY, FAMILIES, FAMILY_ORDER, RELAY_FLOOR_MS, assumed_relay_floor,
                        describe)
from .layered import ALL_LAYERS, BASELINE_LAYERS, DEFAULT_PARAMS, HARDENED_PARAMS, LAYERS
from .providers import PROVIDERS

# Blue playbook, phase 1: counter-measures held for each technique.
PLAYBOOK: Dict[str, List[str]] = {
    "ghost_tap": [],
    "stealth_domestic": ["latency_jump"],
    "latency_shaped": ["latency_jump"],
    "pin_phish_retail": ["latency_jump", "young_terminal"],
    "atm_cashout": ["latency_jump", "atm_anomaly"],
    "fresh_token_cashout": ["latency_jump", "fresh_token_highvalue"],
    "token_churn": ["latency_jump", "terminal_fresh_burst"],
    "seasoned_token": ["chronic_latency", "spend_spike"],
    "low_and_slow": ["latency_jump", "sustained_velocity", "anomalous_spend_accumulation"],
    "cross_border_shaped": ["latency_jump", "new_country"],
    "expired_card": ["expired_card"],
    "brand_mixup": ["aid_brand_mismatch"],
    "cvm_tamper": ["cvm_integrity"],
    "atc_replay": ["atc_regression"],
    "transit_abuse": ["transit_misuse"],
}

# Hardening patches the blue side can trial in phases 2 and 3.
PATCHES: Dict[str, Dict[str, Any]] = {
    "tighten_latency_margin": {
        "param": ("jump_margin_ms", 40.0),
        "why": "Relative-latency margin 55 → 40 ms, closing the band between the relay floor and the threshold."},
    "anomalous_new_terminal": {
        "layer": "anomalous_new_terminal",
        "why": "Relay-like latency at a terminal the token has never used is enough on its own."},
    "fresh_latency_combo": {
        "layer": "fresh_latency_combo",
        "why": "A newly provisioned token tapping with relay-like latency is flagged whatever the amount."},
    "churn_window_24h": {
        "param": ("churn_window_s", DAY),
        "why": "Look back 24 h (not 30 min) for other fresh tokens at the same terminal."},
    "accumulate_7d": {
        "param": ("accum_window_s", 7 * DAY),
        "why": "Accumulate relay-like spend over 7 days so a slow drip is capped."},
    "out_of_area": {
        "layer": "out_of_area",
        "why": "First tap far from anywhere the token has been used, at a new terminal."},
    "displaced_new_token": {
        "layer": "displaced_new_token",
        "why": "A new or never-used wallet first tapped far from the cardholder's home."},
    "dormant_token_first_use": {
        "layer": "dormant_token_first_use",
        "why": "A wallet that sat unused since provisioning and opens with a high-value no-PIN tap."},
    "young_merchant_accumulation": {
        "layer": "young_merchant_accumulation",
        "why": "Repeated high-value spend at merchants that only just appeared."},
    "stranger_merchant_highvalue": {
        "layer": "stranger_merchant_highvalue",
        "why": "High value + just-appeared merchant + a place the token has never been, together."},
    "atm_daily_limit": {
        "layer": "atm_daily_limit",
        "why": "A daily ceiling on contactless ATM withdrawals per token."},
    "unused_token_burst": {
        "param": ("burst_counts_unused", 1),
        "why": "Never-used tokens count toward a terminal burst, not only freshly provisioned ones."},
    "captive_terminal": {
        "layer": "captive_terminal",
        "why": "Token and terminal that have only ever dealt with each other, then a high-value tap."},
    "strong_fresh_burst": {
        "param": ("burst_strong_n", 2),
        "why": "Three or more fresh tokens at one terminal is decisive without any latency evidence."},
}
PHASE2_POOL = ["tighten_latency_margin", "anomalous_new_terminal", "fresh_latency_combo",
               "churn_window_24h", "accumulate_7d"]
PHASE3_POOL = PHASE2_POOL + [
    "out_of_area", "displaced_new_token", "captive_terminal", "strong_fresh_burst",
    "dormant_token_first_use", "young_merchant_accumulation", "stranger_merchant_highvalue",
    "atm_daily_limit", "unused_token_burst"]

MASKED_FLOOR_MS = 50          # phase 3: a relay indistinguishable from a local tap by timing
FPR_BUDGET = 0.005            # a patch that pushes false positives above 0.5% is rejected
TOL_PAYOFF = 200.0            # £ per scenario the red team may still extract
TOL_LEAK = 0.05


class Config:
    def __init__(self, layers: List[str], params: Dict[str, float],
                 applied: Optional[List[str]] = None) -> None:
        self.layers = [n for n in ALL_LAYERS if n in set(layers)]
        self.params = dict(params)
        self.applied = list(applied or [])

    def with_layers(self, names: List[str]) -> "Config":
        return Config(self.layers + [n for n in names if n not in self.layers], self.params, self.applied)

    def with_patch(self, name: str) -> "Config":
        spec = PATCHES[name]
        c = Config(self.layers, self.params, self.applied + [name])
        if "layer" in spec:
            c = Config(c.layers + [spec["layer"]], c.params, c.applied)
        else:
            k, v = spec["param"]
            c.params[k] = v
        return c

    def to_dict(self) -> Dict[str, Any]:
        changed = {k: v for k, v in self.params.items() if DEFAULT_PARAMS.get(k) != v}
        return {"layers": list(self.layers), "param_overrides": changed, "patches": list(self.applied)}


def _fam_view(res: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    return {f: {"prevented": round(a["prevented"], 4), "extracted": round(a["extracted"], 2),
                "attempted": round(a["attempted"], 2), "n": a["n"]}
            for f, a in res["families"].items()}


def _summary(res: Dict[str, Any]) -> Dict[str, Any]:
    return {"robust": len(res["robust"]), "families": len(res["families"]),
            "prevented": round(res["prevented"], 4), "extracted": round(res["extracted"], 2),
            "attempted": round(res["attempted"], 2), "fpr": round(res["fpr"], 5),
            "fp": res["fp"], "n_benign": res["n_benign"], "precision": round(res["precision"], 4)}


def _fuzz_view(fz: Dict[str, Any]) -> Dict[str, Any]:
    return {"leak": round(fz["leak"], 4), "best_payoff": round(fz["best_payoff"], 2),
            "families": {f: {"leak": round(s["leak"], 4), "evade_rate": round(s["evade_rate"], 4),
                             "best_payoff": round(s["best_payoff"], 2), "best": s["best_desc"]}
                         for f, s in fz["families"].items()}}


# --------------------------------------------------------------------------- phase 1
def phase1(cfg: Config, seed: int, n: int, log: Callable[[str], None]):
    plan = arena.default_plan(n)
    res = arena.run(cfg.layers, cfg.params, seed=seed, plan=plan)
    rounds: List[Dict[str, Any]] = []
    tried: set = set()
    log(f"  round 0  baseline: {len(res['robust'])}/{len(res['families'])} families covered, "
        f"{res['prevented'] * 100:.1f}% of attempted value blocked")
    while True:
        weak = [f for f in FAMILY_ORDER if f in res["families"] and f not in res["robust"] and f not in tried]
        if not weak:
            break
        worst = max(weak, key=lambda f: res["families"][f]["extracted"])
        tried.add(worst)
        add = [l for l in PLAYBOOK[worst] if l not in cfg.layers]
        before = res["families"][worst]
        if not add:
            continue
        cfg = cfg.with_layers(add)
        res = arena.run(cfg.layers, cfg.params, seed=seed, plan=plan)
        after = res["families"][worst]
        rounds.append({
            "round": len(rounds) + 1, "target": worst, "label": FAMILIES[worst]["label"],
            "what": FAMILIES[worst]["what"],
            "extracted_before": round(before["extracted"], 2),
            "prevented_before": round(before["prevented"], 4),
            "deployed": add, "prevented_after": round(after["prevented"], 4),
            "summary": _summary(res), "layers": len(cfg.layers),
        })
        log(f"  round {len(rounds):2d}  red: {worst:21s} took £{before['extracted']:>8,.0f} "
            f"| blue: +{', '.join(add)} -> {after['prevented'] * 100:5.1f}% blocked "
            f"| covered {len(res['robust'])}/{len(res['families'])}, FPR {res['fpr'] * 100:.2f}%")
    return cfg, rounds, res


# ----------------------------------------------------------------------- phases 2 / 3
def harden(cfg: Config, pool: List[str], seed: int, floor: float, max_iter: int,
           fz_kwargs: Dict[str, Any], log: Callable[[str], None], competent: bool = False):
    its: List[Dict[str, Any]] = []
    with assumed_relay_floor(floor, competent=competent):
        fz = redteam.fuzz(cfg.layers, cfg.params, seed=seed, **fz_kwargs)
        first = fz
        log(f"  red team: {fz['leak'] * 100:.1f}% of fuzzed attack value leaks; best attack found "
            f"£{fz['best_payoff']:,.0f}")
        for it in range(max_iter):
            if fz["best_payoff"] <= TOL_PAYOFF and fz["leak"] <= TOL_LEAK:
                break
            remaining = [p for p in pool if p not in cfg.applied]
            if not remaining:
                break
            worst = max(fz["families"], key=lambda f: fz["families"][f]["best_payoff"])
            ws = fz["families"][worst]
            rs = seed * 1000 + it
            base_best, _ = redteam.replay_elite(cfg.layers, cfg.params, fz["elite"], rs)
            base_total = sum(base_best.values())
            trials = []
            for name in remaining:
                c2 = cfg.with_patch(name)
                best, fpr = redteam.replay_elite(c2.layers, c2.params, fz["elite"], rs)
                trials.append({"patch": name, "elite_payoff": round(sum(best.values()), 2),
                               "fpr": round(fpr, 5), "accepted": fpr <= FPR_BUDGET})
            ok = [t for t in trials if t["accepted"]]
            if not ok:
                break
            win = min(ok, key=lambda t: t["elite_payoff"])
            if win["elite_payoff"] > base_total * 0.99:
                break                                   # nothing left in the pool helps
            cfg = cfg.with_patch(win["patch"])
            fz2 = redteam.fuzz(cfg.layers, cfg.params, seed=seed + it + 1, **fz_kwargs)
            its.append({
                "iteration": len(its) + 1, "worst_family": worst, "label": FAMILIES[worst]["label"],
                "finding": ws["best_desc"], "finding_payoff": round(ws["best_payoff"], 2),
                "leak_before": round(fz["leak"], 4), "best_before": round(fz["best_payoff"], 2),
                "elite_value_before": round(base_total, 2), "trials": trials,
                "deployed": win["patch"], "why": PATCHES[win["patch"]]["why"],
                "elite_value_after": win["elite_payoff"],
                "leak_after": round(fz2["leak"], 4), "best_after": round(fz2["best_payoff"], 2),
            })
            log(f"  iter {len(its)}  red: {worst} — {ws['best_desc']} (£{ws['best_payoff']:,.0f})\n"
                f"          blue: trialled {len(trials)} patches, deployed `{win['patch']}` "
                f"-> elite value £{base_total:,.0f} → £{win['elite_payoff']:,.0f}; "
                f"re-fuzz leak {fz2['leak'] * 100:.1f}%, best £{fz2['best_payoff']:,.0f}")
            fz = fz2
    return cfg, its, first, fz


def sensitivity(configs: Dict[str, Config], floors: List[float], seed: int, n: int,
                fz_kwargs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """How much protection survives as the assumed relay latency floor drops."""
    rows = []
    for fl in floors:
        row: Dict[str, Any] = {"floor_ms": fl}
        with assumed_relay_floor(fl, competent=True):
            for name, c in configs.items():
                bench = arena.run(c.layers, c.params, seed=seed, plan=arena.default_plan(n))
                fz = redteam.fuzz(c.layers, c.params, seed=seed + 7, **fz_kwargs)
                row[name] = {"benchmark_prevented": round(bench["prevented"], 4),
                             "covered": len(bench["robust"]), "fuzz_leak": round(fz["leak"], 4),
                             "best_payoff": round(fz["best_payoff"], 2)}
        rows.append(row)
    return rows


# ------------------------------------------------------------------------------ run
def run(quick: bool = False, log: Callable[[str], None] = print) -> Dict[str, Any]:
    t_start = time.time()
    n = 8 if quick else 25
    fz_kwargs = {"per_family": 12, "generations": 1} if quick else {"per_family": 40, "generations": 2}
    max_iter = 3 if quick else 14
    val_seeds = [11] if quick else [11, 23, 37]
    floors = [RELAY_FLOOR_MS, MASKED_FLOOR_MS] if quick else [RELAY_FLOOR_MS, 80, 65, MASKED_FLOOR_MS]

    base = Config(BASELINE_LAYERS, DEFAULT_PARAMS)
    log("Phase 1 — technique ladder (worst hole first)")
    cfg1, rounds, _ = phase1(base, seed=1, n=n, log=log)

    log("\nRed-team baseline — fuzzing the original five-layer detector")
    fz_base = redteam.fuzz(base.layers, base.params, seed=500, **fz_kwargs)
    log(f"  {fz_base['leak'] * 100:.1f}% of fuzzed attack value leaks; best attack £{fz_base['best_payoff']:,.0f}")

    log("\nPhase 2 — automated red team vs the laddered detector")
    cfg2, its2, fz2_first, fz2_last = harden(cfg1, PHASE2_POOL, seed=600, floor=RELAY_FLOOR_MS,
                                             max_iter=max_iter, fz_kwargs=fz_kwargs, log=log)

    log(f"\nPhase 3 — the red team is given a latency-masking relay ({MASKED_FLOOR_MS} ms floor)")
    cfg3, its3, fz3_first, fz3_last = harden(cfg2, PHASE3_POOL, seed=700, floor=MASKED_FLOOR_MS,
                                             max_iter=max_iter, fz_kwargs=fz_kwargs, log=log,
                                             competent=True)

    # The loop discovered these counter-measures by one path; the SHIPPED detector
    # (LayeredDetector.full()) enables every layer the loop ever deployed, so it is at
    # least as strong. The headline compares the first release to what actually ships.
    shipped = Config(ALL_LAYERS, HARDENED_PARAMS, applied=cfg3.applied)
    log("\nValidation on unseen seeds, and sensitivity to the latency-floor assumption")
    plan = arena.default_plan(n)
    val = {name: arena.average([arena.run(c.layers, c.params, seed=s, plan=plan) for s in val_seeds])
           for name, c in (("baseline", base), ("phase2", cfg2), ("final", shipped))}
    fz_final = redteam.fuzz(shipped.layers, shipped.params, seed=500, **fz_kwargs)

    log("\nRealistic-world cross-check — the Fraud-Detection-Handbook simulator")
    rw_seeds = [0] if quick else [0, 1]
    rw = [realworld.run(seed=s, nb_days=(20 if quick else 45)) for s in rw_seeds]
    def _rwavg(k, sub=None):
        vals = [(r[k] if sub is None else r[k][sub]) for r in rw]
        return sum(vals) / len(vals)
    rw_out = {
        "rows": sum(r["rows"] for r in rw), "recall": _rwavg("recall"),
        "precision": _rwavg("precision"), "fpr": _rwavg("fpr"),
        "by_scenario": {str(sc): {"recall": sum(r["by_scenario"][sc]["recall"] for r in rw) / len(rw),
                                  "n": sum(r["by_scenario"][sc]["n"] for r in rw)} for sc in (1, 2, 3)},
        "issuer_fraud_recall": _rwavg("issuer_blocking", "fraud_recall"),
        "issuer_legit_decline": _rwavg("issuer_blocking", "legit_decline_rate"),
    }
    log(f"  per-tx FPR {rw_out['fpr'] * 100:.3f}% on an independent fraud model; "
        f"recall {rw_out['recall'] * 100:.1f}% (relay-specialised, by design); "
        f"scenario-2 (skimmed terminal) recall {rw_out['by_scenario']['2']['recall'] * 100:.1f}%")
    sens = sensitivity({"baseline": base, "phase2": cfg2, "final": shipped}, floors, seed=41, n=n,
                       fz_kwargs={"per_family": fz_kwargs["per_family"], "generations": 1})

    groups = lambda layers: len({LAYERS[l][1] for l in layers})
    out = {
        "generated": time.strftime("%Y-%m-%d"), "quick": quick,
        "runtime_s": round(time.time() - t_start, 1),
        "assumptions": {"relay_floor_ms": RELAY_FLOOR_MS, "masked_floor_ms": MASKED_FLOOR_MS,
                        "robust_threshold": arena.ROBUST, "fpr_budget": FPR_BUDGET,
                        "scenarios_per_family": n, "validation_seeds": val_seeds},
        "families": {f: {"label": FAMILIES[f]["label"], "kind": FAMILIES[f]["kind"],
                         "what": FAMILIES[f]["what"]} for f in FAMILY_ORDER},
        "phase1": rounds,
        "phase2": {"iterations": its2, "first": _fuzz_view(fz2_first), "last": _fuzz_view(fz2_last)},
        "phase3": {"iterations": its3, "first": _fuzz_view(fz3_first), "last": _fuzz_view(fz3_last)},
        "fuzz_baseline": _fuzz_view(fz_base), "fuzz_final": _fuzz_view(fz_final),
        "validation": {k: dict(_summary(v), families=_fam_view(v),
                               providers={p: round(a["prevented"], 4) for p, a in v["providers"].items()})
                       for k, v in val.items()},
        "sensitivity": sens,
        "realworld": rw_out,
        "config": {"baseline": base.to_dict(), "phase2": cfg2.to_dict(),
                   "loop_path": cfg3.to_dict(), "final": shipped.to_dict()},
        "counts": {"layers": {"baseline": len(base.layers), "final": len(shipped.layers)},
                   "groups": {"baseline": groups(base.layers), "final": groups(shipped.layers)},
                   "providers": len(PROVIDERS), "families": len(FAMILY_ORDER)},
    }
    b, f = out["validation"]["baseline"], out["validation"]["final"]
    out["headline"] = {
        "families_covered": [b["robust"], f["robust"]],
        "value_blocked": [b["prevented"], f["prevented"]],
        "fuzz_leak": [out["fuzz_baseline"]["leak"], out["fuzz_final"]["leak"]],
        "best_attack": [out["fuzz_baseline"]["best_payoff"], out["fuzz_final"]["best_payoff"]],
        "layers": [len(base.layers), len(shipped.layers)],
        "fpr": [b["fpr"], f["fpr"]], "precision": [b["precision"], f["precision"]],
    }
    return out


# --------------------------------------------------------------------------- report
def _pct(x: float, d: int = 1) -> str:
    return f"{x * 100:.{d}f}%"


def _ratio(a: float, b: float) -> str:
    if a <= 0:
        return "—"
    return f"{b / a:.1f}×"


def render_report(o: Dict[str, Any]) -> str:
    h, c, a = o["headline"], o["counts"], o["assumptions"]
    fb, ff = h["families_covered"]
    vb, vf = h["value_blocked"]
    lb, lf = h["fuzz_leak"]
    pb, pf = h["best_attack"]
    L: List[str] = []
    w = L.append
    w("# Adversarial co-evolution report")
    w("")
    w(f"_Generated {o['generated']} by `python3 -m relayguard.coevolve` "
      f"({o['runtime_s']:.0f} s). Every number below comes from the bundled synthetic "
      "world; none of it is a claim about real authorization data._")
    w("")
    w("## Result")
    w("")
    w("| Measure | First release | After the loop | Change |")
    w("|---|---|---|---|")
    w(f"| Attack families robustly covered (≥{int(a['robust_threshold'] * 100)}% of attempted value blocked) "
      f"| {fb} of {c['families']} | {ff} of {c['families']} | {_ratio(fb, ff)} |")
    w(f"| Attempted fraud value blocked — benchmark, unseen seeds | {_pct(vb)} | {_pct(vf)} | {_ratio(vb, vf)} |")
    w(f"| Fraud value leaking — fuzzed attack space | {_pct(lb)} | {_pct(lf)} | "
      f"{'eliminated' if lf == 0 else _ratio(lf, lb) + ' less'} |")
    w(f"| Best attack the red team could find (per scenario) | £{pb:,.0f} | £{pf:,.0f} | "
      f"{'eliminated' if pf == 0 else _ratio(pf, pb) + ' less'} |")
    w(f"| Detection layers | {c['layers']['baseline']} | {c['layers']['final']} | "
      f"{_ratio(c['layers']['baseline'], c['layers']['final'])} |")
    w(f"| Independent evidence groups | {c['groups']['baseline']} | {c['groups']['final']} | "
      f"{_ratio(c['groups']['baseline'], c['groups']['final'])} |")
    w(f"| Provider profiles with their own rules | none | {c['providers']} | — |")
    w(f"| False-positive rate on genuine taps | {_pct(h['fpr'][0], 2)} | {_pct(h['fpr'][1], 2)} | the cost |")
    w(f"| Precision of a flag | {_pct(h['precision'][0])} | {_pct(h['precision'][1])} | |")
    w("")
    w(f"Benchmark figures are pooled over seeds {a['validation_seeds']}, which the loop never "
      f"tuned against ({a['scenarios_per_family']} scenarios per family per seed). "
      f"The fuzzed rows hold under the stated assumption that a relayed tap cannot get "
      f"below {a['relay_floor_ms']} ms — see *Sensitivity* for what happens when it can.")
    w("")
    w("## How the loop ran")
    w("")
    w("### Phase 1 — technique ladder")
    w("")
    w("Each round the red team runs every family, the family extracting the most money is "
      "picked, and the blue playbook's counter-measures for it are deployed.")
    w("")
    w("| Round | Red team's best technique | Took | Blue deployed | Blocked after | Families covered | FPR |")
    w("|---|---|---|---|---|---|---|")
    for r in o["phase1"]:
        s = r["summary"]
        w(f"| {r['round']} | {r['label']} | £{r['extracted_before']:,.0f} | "
          f"{', '.join('`' + x + '`' for x in r['deployed'])} | {_pct(r['prevented_after'])} | "
          f"{s['robust']} of {s['families']} | {_pct(s['fpr'], 2)} |")
    w("")
    for tag, title, intro in (
        ("phase2", "Phase 2 — automated red team",
         "The fuzzer searches each family's full parameter space. The blue side trials every "
         "remaining patch against the red team's best attacks and deploys the one that removes "
         f"the most value, rejecting any that would push false positives above {_pct(a['fpr_budget'], 1)}."),
        ("phase3", f"Phase 3 — latency-masking relay ({a['masked_floor_ms']} ms floor)",
         "The red team is handed a relay that timing alone cannot distinguish from a local tap. "
         "Only latency-independent counter-measures can help."),
    ):
        ph = o[tag]
        w(f"### {title}")
        w("")
        w(intro)
        w("")
        w(f"Start: {_pct(ph['first']['leak'])} of fuzzed value leaking, best attack "
          f"£{ph['first']['best_payoff']:,.0f}. End: {_pct(ph['last']['leak'])} leaking, best attack "
          f"£{ph['last']['best_payoff']:,.0f}.")
        w("")
        if ph["iterations"]:
            w("| # | What the red team found | Worth | Patch deployed | Red team's best attacks, before → after | Leak after |")
            w("|---|---|---|---|---|---|")
            for it in ph["iterations"]:
                w(f"| {it['iteration']} | **{it['label']}** — {it['finding']} | £{it['finding_payoff']:,.0f} | "
                  f"`{it['deployed']}` — {it['why']} | £{it['elite_value_before']:,.0f} → "
                  f"£{it['elite_value_after']:,.0f} | {_pct(it['leak_after'])} |")
            w("")
        else:
            w("_No patch was needed or none in the pool helped._")
            w("")
    w("## Coverage by attack family")
    w("")
    w("| Family | Type | First release | After the loop | Still leaks to a tuned attacker |")
    w("|---|---|---|---|---|")
    vb_f, vf_f = o["validation"]["baseline"]["families"], o["validation"]["final"]["families"]
    fzf = o["fuzz_final"]["families"]
    for f in o["families"]:
        if f not in vf_f:
            continue
        resid = f"£{fzf[f]['best_payoff']:,.0f}" if f in fzf else "n/a (binary check)"
        w(f"| {o['families'][f]['label']} | {o['families'][f]['kind']} | {_pct(vb_f[f]['prevented'])} | "
          f"{_pct(vf_f[f]['prevented'])} | {resid} |")
    w("")
    w("## Coverage by provider")
    w("")
    w("| Provider | First release | After the loop |")
    w("|---|---|---|")
    pb_, pf_ = o["validation"]["baseline"]["providers"], o["validation"]["final"]["providers"]
    for key, prov in PROVIDERS.items():
        if key in pf_:
            w(f"| {prov.display} | {_pct(pb_.get(key, 0.0))} | {_pct(pf_[key])} |")
    w("")
    w("## Sensitivity: what if relay latency can be hidden?")
    w("")
    w("Most relay coverage depends on a relayed tap being measurably slower than a local one. "
      "This table re-runs the benchmark and the fuzzer while lowering the latency floor the red "
      "team is allowed, with the fuzzer restricted to a competent attacker who stays within "
      "50 ms of that floor. It is the honest measure of depth: what survives when the main "
      "signal is gone.")
    w("")
    w("| Relay floor | First release | After phase 2 | After phase 3 (final) |")
    w("|---|---|---|---|")
    for row in o["sensitivity"]:
        cell = lambda k: (f"{_pct(row[k]['benchmark_prevented'])} blocked · {_pct(row[k]['fuzz_leak'])} leak "
                          f"· best £{row[k]['best_payoff']:,.0f}")
        w(f"| {row['floor_ms']:.0f} ms | {cell('baseline')} | {cell('phase2')} | {cell('final')} |")
    w("")
    rwb = o.get("realworld")
    if rwb:
        w("## Realistic-world cross-check")
        w("")
        w("To avoid grading our own homework, the shipped detector is also run against the "
          "[Fraud-Detection-Handbook](https://fraud-detection-handbook.github.io/) transaction "
          "simulator — an independently-designed model whose fraud is **not** relay: a flat "
          "over-220 rule (scenario 1), skimmed terminals (scenario 2), and account-takeover "
          "amount inflation (scenario 3).")
        w("")
        w(f"- **False-positive rate: {_pct(rwb['fpr'], 3)}** per transaction on "
          f"{rwb['rows']:,} transactions from a world it was never tuned on — the detector "
          "does not misfire on an unfamiliar but legitimate population.")
        w(f"- **Recall: {_pct(rwb['recall'])}** — low *by design*. RelayGuard detects relay, "
          "not generic card fraud; the two threat models barely overlap.")
        w("")
        w("| Handbook fraud scenario | What it is | RelayGuard recall |")
        w("|---|---|---|")
        names = {"1": "Flat over-£220 rule", "2": "Skimmed / compromised terminal",
                 "3": "Account-takeover amount inflation (×5)"}
        for sc in ("1", "2", "3"):
            w(f"| Scenario {sc} | {names[sc]} | {_pct(rwb['by_scenario'][sc]['recall'])} |")
        w("")
        w("The honest limitation this surfaces: **scenario 2 is near-uncatchable from "
          "transaction features alone** — a normal-looking tap on a skimmed terminal carries "
          "no signal. Catching it needs issuer *fraud-feedback* (mark a terminal risky once "
          "confirmed-fraud taps appear on it), which this detector does not yet consume. That "
          "is the next layer to build, and it is recorded here rather than hidden.")
        w("")
    w("## Final configuration")
    w("")
    fc = o["config"]["final"]
    w(f"- **Layers ({len(fc['layers'])}):** " + ", ".join(f"`{x}`" for x in fc["layers"]))
    w(f"- **Parameter changes from defaults:** " + (", ".join(f"`{k}={v:g}`" for k, v in fc["param_overrides"].items()) or "none"))
    w(f"- **Patches in the order deployed:** " + (", ".join(f"`{x}`" for x in fc["patches"]) or "none"))
    w("")
    w("`LayeredDetector.full()` builds exactly this configuration (every layer the loop "
      "deployed, plus the few it did not need this run, with the hardened parameters).")
    w("")
    w("## What this does not show")
    w("")
    w("- **Synthetic world.** Benign behaviour, latency distributions and attack economics are "
      "modelled, not measured. Weights and thresholds would need calibrating on real data.")
    w("- **Authored counter-measures.** The loop automates the search for holes, their ranking, "
      "patch trials and regression gating. A person wrote each counter-measure.")
    w("- **One attacker model.** The red team only explores the families and parameters defined in "
      "`adversary.py`. An attack outside that space is not tested — for example several victims "
      "funnelled through one long-established complicit merchant.")
    w("- **Relay-specialised.** The realistic-world cross-check shows it is not a general fraud "
      "detector; generic amount fraud and skimmed-terminal fraud need complementary controls.")
    w("- **Latency is the load-bearing signal.** See the sensitivity table. The durable fix for "
      "relay is distance bounding at the terminal; this detector is a compensating control.")
    w("")
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser(description="RelayGuard adversarial co-evolution loop")
    ap.add_argument("--quick", action="store_true", help="small smoke run (CI)")
    ap.add_argument("--out", default=".", help="directory for ADVERSARIAL_REPORT.md and reports/")
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()
    o = run(quick=args.quick)
    h = o["headline"]
    print(f"\nDONE in {o['runtime_s']:.0f}s — families covered {h['families_covered'][0]} → "
          f"{h['families_covered'][1]} of {o['counts']['families']}; value blocked "
          f"{h['value_blocked'][0] * 100:.1f}% → {h['value_blocked'][1] * 100:.1f}%; "
          f"fuzz leak {h['fuzz_leak'][0] * 100:.1f}% → {h['fuzz_leak'][1] * 100:.1f}%; "
          f"FPR {h['fpr'][1] * 100:.2f}%")
    if args.no_write:
        return
    os.makedirs(os.path.join(args.out, "reports"), exist_ok=True)
    with open(os.path.join(args.out, "reports", "coevolution.json"), "w") as fh:
        json.dump(o, fh, indent=1)
    with open(os.path.join(args.out, "ADVERSARIAL_REPORT.md"), "w") as fh:
        fh.write(render_report(o))
    print("wrote ADVERSARIAL_REPORT.md and reports/coevolution.json")


if __name__ == "__main__":
    main()
