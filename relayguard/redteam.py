"""Automated red team: search the attacker's parameter space for what still gets through.

For every relay family the fuzzer
  1. samples genomes from the family's *full legal space* (not just the textbook
     version) and measures how much of the attempted value leaks        -> `leak`
  2. keeps the most profitable evasions and mutates them for a few generations
  3. re-runs the best few several times so a lucky draw is not reported  -> `best_payoff`

The output tells the blue team where the largest hole is and how much it is worth.
Everything is synthetic feature records scored by our own detector; see adversary.py.
"""
from __future__ import annotations

import random
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import arena
from .adversary import FAMILIES, RELAY_FAMILIES, describe, mutate, sample_space

Scored = Tuple[Dict[str, Any], float, float]          # (genome, attempted, extracted)


def _evaluate(layers: Iterable[str], params: Optional[Dict[str, float]],
              pop: Dict[str, List[Dict[str, Any]]], seed: int,
              chunk: int = 20) -> Tuple[Dict[str, List[Scored]], float]:
    layers = list(layers)
    out: Dict[str, List[Scored]] = {f: [] for f in pop}
    n_benign = fp = 0
    n_chunks = max((len(v) + chunk - 1) // chunk for v in pop.values()) if pop else 0
    for ci in range(n_chunks):
        plan = {f: v[ci * chunk:(ci + 1) * chunk] for f, v in pop.items()}
        plan = {f: v for f, v in plan.items() if v}
        res = arena.run(layers, params, seed=seed + ci, plan=plan, keep_scenarios=True)
        n_benign += res["n_benign"]
        fp += res["fp"]
        for m in res["scenario_detail"].values():
            if m["valid"]:
                out[m["family"]].append((m["genome"], m["attempted"], m["extracted"]))
    return out, (fp / n_benign if n_benign else 0.0)


def replay_elite(layers: Iterable[str], params: Optional[Dict[str, float]],
                 elite: Dict[str, List[Dict[str, Any]]], seed: int,
                 replicas: int = 4) -> Tuple[Dict[str, float], float]:
    """Re-run each family's best genomes `replicas` times. Returns the best mean
    payoff per family (£ per scenario) and the false-positive rate of the run."""
    pop = {f: [g for g in gs[:5] for _ in range(replicas)] for f, gs in elite.items() if gs}
    scored, fpr = _evaluate(layers, params, pop, seed)
    best: Dict[str, float] = {}
    for f, rows in scored.items():
        per: Dict[int, List[float]] = {}
        for g, _, ext in rows:
            per.setdefault(id(g), []).append(ext)
        best[f] = max((sum(v) / len(v) for v in per.values()), default=0.0)
    return best, fpr


def fuzz(layers: Iterable[str], params: Optional[Dict[str, float]] = None, seed: int = 101,
         per_family: int = 40, generations: int = 2,
         families: Optional[List[str]] = None) -> Dict[str, Any]:
    layers = list(layers)
    families = families or RELAY_FAMILIES
    rng = random.Random(seed)
    pop = {f: [sample_space(FAMILIES[f]["space"], rng) for _ in range(per_family)] for f in families}
    gen0, _ = _evaluate(layers, params, pop, seed * 100)

    stats: Dict[str, Dict[str, Any]] = {}
    tot_att = tot_ext = 0.0
    for f in families:
        att = sum(a for _, a, _ in gen0[f])
        ext = sum(e for _, _, e in gen0[f])
        tot_att += att
        tot_ext += ext
        stats[f] = {"n": len(gen0[f]), "leak": ext / att if att else 0.0,
                    "evade_rate": (sum(1 for _, _, e in gen0[f] if e > 0) / len(gen0[f])) if gen0[f] else 0.0}

    elite: Dict[str, List[Scored]] = {f: sorted(gen0[f], key=lambda x: -x[2])[:10] for f in families}
    for gen in range(generations):
        kids = {f: [mutate(g, FAMILIES[f]["space"], rng) for (g, _, _) in elite[f] for _ in range(2)]
                for f in families}
        scored, _ = _evaluate(layers, params, kids, seed * 100 + 37 * (gen + 1))
        for f in families:
            elite[f] = sorted(elite[f] + scored[f], key=lambda x: -x[2])[:10]

    elite_genomes = {f: [g for (g, _, _) in elite[f]] for f in families}
    best, _ = replay_elite(layers, params, elite_genomes, seed * 100 + 991)
    for f in families:
        stats[f]["best_payoff"] = best.get(f, 0.0)
        stats[f]["best_genome"] = elite_genomes[f][0] if elite_genomes[f] else {}
        stats[f]["best_desc"] = describe(stats[f]["best_genome"])
    return {"families": stats, "leak": tot_ext / tot_att if tot_att else 0.0,
            "best_payoff": max((s["best_payoff"] for s in stats.values()), default=0.0),
            "elite": elite_genomes}
