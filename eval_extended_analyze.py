#!/usr/bin/env python3
"""Parse [DRL_EVAL] log + scenario CSV → per-scenario + overall F1."""
import sys, re, csv
from collections import defaultdict

if len(sys.argv) < 3:
    print("usage: eval_extended_analyze.py <log_file> <scen_csv>")
    sys.exit(1)

LOG_FILE, SCEN_CSV = sys.argv[1], sys.argv[2]

EVAL_RE = re.compile(
    r"\[DRL_EVAL\] ts=(\d+) meid=\S+ ue_id=(\d+) ppo=(-?\d+) "
    r"thp_dl=(\d+) thp_ul=(\d+) prb_used_dl=(\d+) prb_used_ul=(\d+)"
)

# Load samples
samples = []  # (ts_ms, ue, ppo, thp_dl, thp_ul, prb_dl, prb_ul)
with open(LOG_FILE) as f:
    for line in f:
        m = EVAL_RE.search(line)
        if not m:
            continue
        ts, ue, ppo, td, tu, pd, pu = m.groups()
        samples.append((int(ts), int(ue), int(ppo), int(td), int(tu), int(pd), int(pu)))
print(f"[Analyze] parsed {len(samples)} DRL_EVAL samples")

# Load scenarios
scenarios = []  # list of dicts
with open(SCEN_CSV) as f:
    for row in csv.DictReader(f):
        scenarios.append({
            "name": row["scenario"],
            "ue": int(row["ue_pov"]),
            "label": int(row["label"]),
            "start": int(row["start_ms"]),
            "end": int(row["end_ms"]),
        })

# Aggregate
scen_stats = defaultdict(lambda: {"tp":0,"fp":0,"fn":0,"tn":0,"n":0,"active":0})
overall = {"tp":0,"fp":0,"fn":0,"tn":0}

# Pre-index samples by ue for speed (not strictly needed for small N)
for sc in scenarios:
    key = (sc["name"], sc["ue"])
    lbl = sc["label"]
    for ts, ue, ppo, td, tu, pd, pu in samples:
        if ue != sc["ue"]: continue
        if ts < sc["start"] or ts > sc["end"]: continue
        scen_stats[key]["n"] += 1
        # Count "active" (non-idle) samples — useful diagnostic
        if (td + tu + pd + pu) > 0:
            scen_stats[key]["active"] += 1
        pred = 1 if ppo == 1 else 0
        if lbl == 1 and pred == 1: scen_stats[key]["tp"] += 1
        elif lbl == 0 and pred == 1: scen_stats[key]["fp"] += 1
        elif lbl == 1 and pred == 0: scen_stats[key]["fn"] += 1
        elif lbl == 0 and pred == 0: scen_stats[key]["tn"] += 1

print()
print(f"{'Scenario':22s} | {'UE':>2s} {'L':>2s} | {'N':>5s} {'act':>5s} | {'TP':>5s} {'FP':>5s} {'FN':>5s} {'TN':>5s} | {'P':>5s} {'R':>5s} {'F1':>5s}")
print("-" * 100)
for sc in scenarios:
    key = (sc["name"], sc["ue"])
    s = scen_stats[key]
    P = s["tp"]/max(s["tp"]+s["fp"],1)
    R = s["tp"]/max(s["tp"]+s["fn"],1) if sc["label"]==1 else 1.0
    F1 = 2*P*R/max(P+R,1e-9) if (s["tp"]+s["fp"]+s["fn"])>0 else (1.0 if sc["label"]==0 and s["fp"]==0 else 0.0)
    # For label=0 scenarios, "F1" interpretation is awkward — show TN-rate instead
    if sc["label"] == 0:
        spec = s["tn"]/max(s["tn"]+s["fp"],1)
        f1_str = f"{spec:.3f}*"   # * = specificity for benign UE
    else:
        f1_str = f"{F1:.3f}"
    print(f"{sc['name']:22s} | {sc['ue']:>2d} {sc['label']:>2d} | {s['n']:>5d} {s['active']:>5d} | "
          f"{s['tp']:>5d} {s['fp']:>5d} {s['fn']:>5d} {s['tn']:>5d} | "
          f"{P:.3f} {R:.3f} {f1_str:>5s}")
    overall["tp"] += s["tp"]; overall["fp"] += s["fp"]; overall["fn"] += s["fn"]; overall["tn"] += s["tn"]

P = overall["tp"]/max(overall["tp"]+overall["fp"],1)
R = overall["tp"]/max(overall["tp"]+overall["fn"],1)
F1 = 2*P*R/max(P+R,1e-9)
ACC = (overall["tp"]+overall["tn"])/max(sum(overall.values()),1)
SPEC = overall["tn"]/max(overall["tn"]+overall["fp"],1)
FPR = overall["fp"]/max(overall["fp"]+overall["tn"],1)

print()
print("═══════════ OVERALL ═══════════")
print(f"  Samples: {sum(overall.values())}  (TP={overall['tp']} FP={overall['fp']} FN={overall['fn']} TN={overall['tn']})")
print(f"  Precision : {P:.4f}")
print(f"  Recall    : {R:.4f}")
print(f"  F1-Score  : {F1:.4f}")
print(f"  Accuracy  : {ACC:.4f}")
print(f"  Specificity (TNR): {SPEC:.4f}")
print(f"  FPR       : {FPR:.4f}")
print()
print("Note: F1* (with star) for label=0 scenarios = Specificity (TN-rate)")
