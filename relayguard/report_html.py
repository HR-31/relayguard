"""Render reports/coevolution.json into a standalone, self-contained HTML dashboard.

    python3 -m relayguard.report_html            # reads reports/coevolution.json
    python3 -m relayguard.report_html out.html

The data is inlined into the page, so it opens straight from disk (no server, no
fetch). Charts are hand-built SVG so there are no dependencies.
"""
import json
import os
import sys
from typing import Any, Dict

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RelayGuard — adversarial co-evolution</title>
<style>
  :root{
    color-scheme: light dark;
    --surface:#fcfcfb; --panel:#ffffff; --line:#e6e4df; --ink:#15150f; --muted:#5f5e57;
    --blue:#2a78d6; --red:#d03b3b; --good:#0ca30c; --amber:#eda100; --track:#eceae4;
    --shadow:0 1px 3px rgba(20,20,15,.07);
  }
  @media (prefers-color-scheme: dark){
    :root{--surface:#15151a; --panel:#1c1c22; --line:#2c2c34; --ink:#f0efe8; --muted:#a3a299;
      --blue:#3987e5; --red:#e66767; --good:#2bbd2b; --amber:#e0b64b; --track:#262630;
      --shadow:0 1px 3px rgba(0,0,0,.4);}
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--surface);color:var(--ink);line-height:1.5;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Arial,sans-serif}
  .wrap{max-width:900px;margin:0 auto;padding:30px 22px 60px}
  .kick{font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--blue);font-weight:700}
  h1{font-size:1.7rem;margin:.2rem 0 .3rem}
  .sub{color:var(--muted);font-size:.93rem;margin-bottom:6px}
  .note{color:var(--muted);font-size:.78rem}
  h2{font-size:1.04rem;margin:30px 0 4px;display:flex;align-items:center;gap:9px}
  h2 .b{width:22px;height:4px;border-radius:2px;background:var(--blue)}
  .hero{display:flex;flex-wrap:wrap;gap:14px;margin:18px 0 6px}
  .big{flex:1;min-width:150px;background:var(--panel);border:1px solid var(--line);border-radius:12px;
    padding:15px 16px;box-shadow:var(--shadow)}
  .big .n{font-size:1.9rem;font-weight:800;line-height:1}
  .big .n .arrow{color:var(--muted);font-weight:600;font-size:1.1rem;margin:0 5px}
  .big .cap{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:6px}
  .big .mult{display:inline-block;font-size:.72rem;font-weight:700;color:var(--good);
    background:color-mix(in srgb, var(--good) 14%, transparent);border-radius:999px;padding:1px 8px;margin-top:7px}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;
    box-shadow:var(--shadow);margin-top:10px}
  table{border-collapse:collapse;width:100%;font-size:.84rem}
  th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
  th{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
  td.r,th.r{text-align:right;font-variant-numeric:tabular-nums}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82em;
    background:var(--track);border-radius:4px;padding:0 5px}
  .legend{display:flex;gap:16px;font-size:.78rem;color:var(--muted);margin:10px 0 2px;flex-wrap:wrap}
  .sw{width:10px;height:10px;border-radius:2px;display:inline-block;margin-right:5px;vertical-align:middle}
  .barrow{display:grid;grid-template-columns:150px 1fr;gap:10px;align-items:center;margin:7px 0}
  .barrow .lab{font-size:.82rem}
  .track{position:relative;height:22px;background:var(--track);border-radius:5px;overflow:hidden}
  .fill{position:absolute;top:0;bottom:0;left:0;border-radius:5px;display:flex;align-items:center;
    justify-content:flex-end;padding-right:6px;font-size:.7rem;font-weight:700;color:#fff}
  .tag{font-size:.64rem;font-weight:700;border-radius:999px;padding:1px 7px}
  .tag.red{color:var(--red);background:color-mix(in srgb,var(--red) 14%,transparent)}
  .tag.good{color:var(--good);background:color-mix(in srgb,var(--good) 14%,transparent)}
  .foot{color:var(--muted);font-size:.76rem;margin-top:26px;border-top:1px solid var(--line);padding-top:14px}
  .warn{background:color-mix(in srgb,var(--amber) 10%,transparent);border:1px solid color-mix(in srgb,var(--amber) 35%,transparent);
    border-radius:10px;padding:11px 14px;font-size:.85rem;margin-top:10px}
</style>
</head>
<body>
<div class="wrap">
  <div class="kick">RelayGuard · red-team / blue-team co-evolution</div>
  <h1 id="title">Hardening a relay-fraud detector in a loop</h1>
  <div class="sub" id="sub"></div>
  <div class="note" id="asof"></div>

  <div class="hero" id="hero"></div>

  <h2><span class="b"></span>Baseline vs. evolved detector</h2>
  <div class="panel">
    <div class="legend">
      <span><span class="sw" style="background:var(--red)"></span>first release (5 layers)</span>
      <span><span class="sw" style="background:var(--blue)"></span>after the loop</span>
    </div>
    <div id="compare"></div>
  </div>

  <h2><span class="b"></span>Phase 1 — the attack ladder</h2>
  <div class="sub">Each round the red team runs every family; the costliest hole is patched; repeat.</div>
  <div class="panel" style="overflow-x:auto"><table id="ladder"></table></div>

  <h2><span class="b"></span>Phases 2 & 3 — automated red team</h2>
  <div class="sub">A fuzzer searches each attack's full parameter space; the blue side deploys the patch that removes the most value within the false-positive budget.</div>
  <div class="panel" style="overflow-x:auto"><table id="iters"></table></div>

  <h2><span class="b"></span>Coverage by attack family</h2>
  <div class="panel" style="overflow-x:auto"><table id="families"></table></div>

  <h2><span class="b"></span>Coverage by provider</h2>
  <div class="panel" style="overflow-x:auto"><table id="providers"></table></div>

  <h2><span class="b"></span>Sensitivity — what if relay latency can be hidden?</h2>
  <div class="sub">Latency is the load-bearing signal. This lowers the relay's assumed latency floor and re-attacks — the honest measure of depth.</div>
  <div class="panel" style="overflow-x:auto"><table id="sens"></table></div>
  <div class="warn" id="sensnote"></div>

  <h2 id="rwh" style="display:none"><span class="b"></span>Realistic-world cross-check (independent fraud model)</h2>
  <div class="sub" id="rwsub" style="display:none"></div>
  <div class="panel" id="rwpanel" style="display:none;overflow-x:auto"></div>

  <div class="foot" id="foot"></div>
</div>

<script id="data" type="application/json">__DATA__</script>
<script>
const O = JSON.parse(document.getElementById("data").textContent);
const pct = (x,d=1)=>(x*100).toFixed(d)+"%";
const gbp = x=>"£"+Math.round(x).toLocaleString();
const ratio=(a,b)=> a<=0?"—":(b/a).toFixed(1)+"×";
const el=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e;};

document.getElementById("sub").textContent =
  "A detector is attacked, patched, and re-attacked until every modelled relay-fraud technique is covered — then stress-tested past its core assumption.";
document.getElementById("asof").textContent =
  `Generated ${O.generated} · ${O.runtime_s}s · ${O.quick?"quick mode":"full run"} · all figures from the bundled synthetic world`;

const h=O.headline, c=O.counts;
const hero=[
  ["Attack families covered", h.families_covered[0]+" / "+c.families, h.families_covered[1]+" / "+c.families, ratio(h.families_covered[0],h.families_covered[1])],
  ["Fraud value blocked", pct(h.value_blocked[0]), pct(h.value_blocked[1]), ratio(h.value_blocked[0],h.value_blocked[1])],
  ["Detection layers", h.layers[0], h.layers[1], ratio(h.layers[0],h.layers[1])],
  ["Best attack found", gbp(h.best_attack[0]), (h.best_attack[1]>0?gbp(h.best_attack[1]):"£0"), h.best_attack[1]==0?"eliminated":ratio(h.best_attack[1],h.best_attack[0])+" less"],
];
const hc=document.getElementById("hero");
hero.forEach(([cap,a,b,m])=>{
  const d=el("div","big");
  d.innerHTML=`<div class="n"><span style="color:var(--red)">${a}</span><span class="arrow">→</span><span style="color:var(--blue)">${b}</span></div>`+
              `<div class="cap">${cap}</div><div class="mult">${m}</div>`;
  hc.appendChild(d);
});

// comparison bars (normalised each row to its own max)
const comp=[
  ["Families covered", h.families_covered[0], h.families_covered[1], v=>v],
  ["Value blocked", h.value_blocked[0], h.value_blocked[1], v=>pct(v)],
  ["Detection layers", h.layers[0], h.layers[1], v=>v],
  ["Evidence groups", c.groups.baseline, c.groups.final, v=>v],
  ["Providers w/ rules", 0, c.providers, v=>v],
];
const cc=document.getElementById("compare");
comp.forEach(([lab,a,b,fmt])=>{
  const mx=Math.max(a,b,1);
  const mk=(v,color)=>`<div class="barrow"><div class="lab">${lab}</div><div class="track">`+
    `<div class="fill" style="width:${Math.max(4,v/mx*100)}%;background:${color}">${fmt(v)}</div></div></div>`;
  cc.insertAdjacentHTML("beforeend", mk(a,"var(--red)"));
  cc.insertAdjacentHTML("beforeend", mk(b,"var(--blue)"));
});

// phase 1 ladder
let t=document.getElementById("ladder");
t.innerHTML="<tr><th>#</th><th>Red team's costliest technique</th><th class='r'>Took</th><th>Blue deployed</th><th class='r'>Blocked after</th><th class='r'>Covered</th></tr>";
O.phase1.forEach(r=>{
  t.insertAdjacentHTML("beforeend",
    `<tr><td class='r'>${r.round}</td><td>${r.label}</td><td class='r'>${gbp(r.extracted_before)}</td>`+
    `<td>${r.deployed.map(x=>`<code>${x}</code>`).join(" ")}</td><td class='r'>${pct(r.prevented_after)}</td>`+
    `<td class='r'>${r.summary.robust}/${r.summary.families}</td></tr>`);
});

// phases 2+3 iterations
t=document.getElementById("iters");
t.innerHTML="<tr><th>Phase</th><th>What the red team found</th><th class='r'>Worth</th><th>Patch deployed</th><th class='r'>Leak after</th></tr>";
[["2",O.phase2],["3",O.phase3]].forEach(([ph,blk])=>{
  if(!blk.iterations.length){
    t.insertAdjacentHTML("beforeend",`<tr><td>${ph}</td><td colspan="4" class="note">no further patch needed</td></tr>`);
  }
  blk.iterations.forEach(it=>{
    t.insertAdjacentHTML("beforeend",
      `<tr><td>${ph}</td><td><b>${it.label}</b> — ${it.finding}</td><td class='r'>${gbp(it.finding_payoff)}</td>`+
      `<td><code>${it.deployed}</code><div class="note">${it.why}</div></td><td class='r'>${pct(it.leak_after)}</td></tr>`);
  });
});

// families
t=document.getElementById("families");
t.innerHTML="<tr><th>Attack family</th><th>Type</th><th class='r'>First release</th><th class='r'>After loop</th></tr>";
const vb=O.validation.baseline.families, vf=O.validation.final.families;
Object.keys(O.families).forEach(f=>{
  if(!(f in vf))return;
  const tag=O.families[f].kind=="protocol"?'<span class="tag">protocol</span>':'<span class="tag">relay</span>';
  t.insertAdjacentHTML("beforeend",
    `<tr><td>${O.families[f].label}</td><td>${tag}</td><td class='r' style="color:var(--red)">${pct(vb[f].prevented)}</td>`+
    `<td class='r' style="color:var(--good)">${pct(vf[f].prevented)}</td></tr>`);
});

// providers
t=document.getElementById("providers");
t.innerHTML="<tr><th>Provider</th><th class='r'>First release</th><th class='r'>After loop</th></tr>";
const pb=O.validation.baseline.providers, pf=O.validation.final.providers;
Object.keys(pf).forEach(k=>{
  t.insertAdjacentHTML("beforeend",
    `<tr><td>${k}</td><td class='r' style="color:var(--red)">${pct(pb[k]||0)}</td><td class='r' style="color:var(--good)">${pct(pf[k])}</td></tr>`);
});

// sensitivity
t=document.getElementById("sens");
t.innerHTML="<tr><th class='r'>Relay latency floor</th><th class='r'>First release</th><th class='r'>After phase 2</th><th class='r'>Final</th></tr>";
const cell=o=>`${pct(o.benchmark_prevented,0)} blocked · ${pct(o.fuzz_leak,0)} leak`;
O.sensitivity.forEach(r=>{
  t.insertAdjacentHTML("beforeend",
    `<tr><td class='r'>${r.floor_ms} ms</td><td class='r'>${cell(r.baseline)}</td><td class='r'>${cell(r.phase2)}</td><td class='r'>${cell(r.final)}</td></tr>`);
});
document.getElementById("sensnote").innerHTML =
  "As the relay gets faster (floor drops toward a local tap's latency), timing-based coverage erodes and the latency-independent layers (<code>captive_terminal</code>, <code>out_of_area</code>, token-geography) carry what remains. The durable fix for relay is distance bounding at the terminal; this detector is a compensating control.";

// realistic-world cross-check
if(O.realworld){
  const rw=O.realworld;
  document.getElementById("rwh").style.display="";
  const sub=document.getElementById("rwsub"); sub.style.display="";
  sub.innerHTML="Run against the <b>Fraud-Detection-Handbook</b> simulator — an independently-designed fraud model (not relay). The point: confirm the detector doesn't misfire on an unfamiliar legitimate population, and surface where it doesn't generalise.";
  const names={"1":"Flat over-£220 rule","2":"Skimmed / compromised terminal","3":"Account-takeover (×5 amount)"};
  const p=document.getElementById("rwpanel"); p.style.display="";
  let rows=`<div class="barrow"><div class="lab">Per-tx false positives</div><div class="track"><div class="fill" style="width:${Math.min(100,rw.fpr*100*20+4)}%;background:var(--good)">${pct(rw.fpr,3)}</div></div></div>`;
  p.innerHTML=`<p class="note" style="margin-top:0">On ${rw.rows.toLocaleString()} transactions from a world it was never tuned on: <b style="color:var(--good)">${pct(rw.fpr,3)}</b> false-positive rate, and <b>${pct(rw.recall)}</b> recall — <i>low by design</i>, because RelayGuard detects relay, not generic card fraud.</p>`+rows+
    `<table style="margin-top:10px"><tr><th>Handbook fraud scenario</th><th>What it is</th><th class='r'>RelayGuard recall</th></tr>`+
    ["1","2","3"].map(s=>`<tr><td>Scenario ${s}</td><td>${names[s]}</td><td class='r'>${pct(rw.by_scenario[s].recall)}</td></tr>`).join("")+`</table>`+
    `<div class="warn" style="margin-top:12px"><b>Honest limitation:</b> scenario 2 (a normal-looking tap on a skimmed terminal) carries no transaction-level signal and is near-uncatchable without issuer <b>fraud-feedback</b> — marking a terminal risky once confirmed-fraud taps appear on it. That's the next layer to build; it's recorded, not hidden.</div>`;
}

document.getElementById("foot").innerHTML =
  "<b>What this is:</b> the loop automates the red-team search, ranks holes by value, trials patches and gates them on a false-positive budget. The counter-measures themselves are authored. "+
  "<b>What this is not:</b> a claim about real authorization data — the benign behaviour, latency distributions and attack economics are modelled in <code>adversary.py</code>, not measured.";
</script>
</body>
</html>
"""


def render(data: Dict[str, Any]) -> str:
    return TEMPLATE.replace("__DATA__", json.dumps(data))


def main() -> None:
    src = os.path.join(HERE, "reports", "coevolution.json")
    if not os.path.exists(src):
        sys.exit("reports/coevolution.json not found — run `python3 -m relayguard.coevolve` first")
    with open(src) as fh:
        data = json.load(fh)
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "reports", "coevolution.html")
    with open(out, "w") as fh:
        fh.write(render(data))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
