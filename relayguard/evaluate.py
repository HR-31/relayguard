"""Evaluation harness: run the detector over a labelled stream and print metrics.

    python3 -m relayguard.evaluate [--tokens N] [--seed S] [--threshold T]

Prints a confusion matrix plus recall / precision / FPR / accuracy and a per-attack
breakdown. This is the "proof" artefact — it turns the demo into a number.
"""
import argparse

from .detector import RelayDetector, FLAG_THRESHOLD
from .simulator import generate, summary


def evaluate(rows, threshold=FLAG_THRESHOLD):
    det = RelayDetector(threshold=threshold)
    tp = fp = tn = fn = 0
    missed_by_style = {"ghost_tap": 0, "stealth": 0}
    caught_by_style = {"ghost_tap": 0, "stealth": 0}
    for tx in rows:
        res = det.score(tx)
        flagged = res.verdict == "RELAY"
        if tx["is_relay"]:
            if flagged:
                tp += 1
                caught_by_style[tx["attack"]] += 1
            else:
                fn += 1
                missed_by_style[tx["attack"]] += 1
        else:
            if flagged:
                fp += 1
            else:
                tn += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": recall, "precision": precision, "fpr": fpr, "accuracy": accuracy,
        "caught_by_style": caught_by_style, "missed_by_style": missed_by_style,
    }


def main():
    ap = argparse.ArgumentParser(description="RelayGuard evaluation harness")
    ap.add_argument("--tokens", type=int, default=14)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--threshold", type=int, default=FLAG_THRESHOLD)
    args = ap.parse_args()

    rows = generate(num_tokens=args.tokens, seed=args.seed)
    s = summary(rows)
    m = evaluate(rows, threshold=args.threshold)

    bar = "=" * 56
    print(bar)
    print("RelayGuard — detection evaluation")
    print(bar)
    print(f"stream           : {s['total']} transactions "
          f"({s['legit']} legit, {s['relay']} relay)")
    print(f"relay styles     : {s['ghost_tap']} ghost_tap, {s['stealth']} stealth")
    print(f"flag threshold   : score >= {args.threshold}")
    print("-" * 56)
    print("confusion matrix              predicted")
    print("                        RELAY        LEGIT")
    print(f"  actual RELAY     {m['tp']:>7} (TP) {m['fn']:>7} (FN)")
    print(f"  actual LEGIT     {m['fp']:>7} (FP) {m['tn']:>7} (TN)")
    print("-" * 56)
    print(f"  recall (detection rate) : {m['recall']*100:6.1f}%  "
          f"(relays caught)")
    print(f"  precision               : {m['precision']*100:6.1f}%  "
          f"(flags that were real)")
    print(f"  false-positive rate     : {m['fpr']*100:6.1f}%  "
          f"(legit wrongly flagged)")
    print(f"  accuracy                : {m['accuracy']*100:6.1f}%")
    print("-" * 56)
    print(f"  ghost_tap : {m['caught_by_style']['ghost_tap']} caught, "
          f"{m['missed_by_style']['ghost_tap']} missed")
    print(f"  stealth   : {m['caught_by_style']['stealth']} caught, "
          f"{m['missed_by_style']['stealth']} missed  (the hard case)")
    print(bar)


if __name__ == "__main__":
    main()
