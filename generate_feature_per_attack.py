#!/usr/bin/env python3
"""Per-attack-type feature importance using the production v7.4 27-dim obs.

Replays real-testbed KPM samples through the actual SelfFeatureEngineer
to reconstruct the 27-dim obs vector each sample. Then for each attack
scenario computes Cohen's d per feature vs the pooled idle baseline.

Output: figures/fig_feature_per_attack.png  (heatmap rows=features × cols=attacks)
"""
import os, re, csv, sys
from collections import defaultdict
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, "/home/nttrung/my-xapp/src")
from drl_agent_nue import (
    SelfFeatureEngineer, EwmaTracker, normalize_raw_nue,
    OBS_DIM_NUE, EWMA_ALPHA,
)
# population_features + interaction_nue_features are top-level
import drl_agent_nue as A

OUT = "/home/nttrung/my-xapp/figures"
os.makedirs(OUT, exist_ok=True)

FEATURE_NAMES = [
    "thp_dl", "thp_ul", "prb_used_dl", "prb_used_ul",
    "prb_avail_dl", "delay_ul", "delay_dl",
    "util_ratio", "ul_dl_ratio", "prb_efficiency", "burstiness", "delay_jitter",
    "nonzero_ratio", "peak_to_mean_norm", "zero_runs",
    "zscore_thp_self", "zscore_prb_self", "zscore_delay_self",
    "prb_share", "thp_zscore_pop", "prb_zscore_pop", "total_load", "thp_gini",
    "is_top_prb", "is_top_thp", "victim_signal", "dominance",
]
assert len(FEATURE_NAMES) == OBS_DIM_NUE, f"{len(FEATURE_NAMES)} vs {OBS_DIM_NUE}"

GROUP_OF = (["raw"]*7 + ["eng+timing"]*8 + ["zscore"]*3
            + ["population"]*5 + ["interaction"]*4)
GROUP_COLOR = {
    "raw":"#1f77b4","eng+timing":"#ff7f0e","zscore":"#8c564b",
    "population":"#d62728","interaction":"#9467bd",
}

EVAL_RE = re.compile(
    r"\[DRL_EVAL\] ts=(\d+) meid=\S+ ue_id=(\d+) ppo=(-?\d+) "
    r"thp_dl=([\d.]+) thp_ul=([\d.]+) prb_used_dl=([\d.]+) prb_used_ul=([\d.]+) "
    r"prb_avail=([\d.]+) delay_ul=([\d.]+) delay_dl=([\d.]+)"
)

def parse_log(path):
    out = []
    with open(path) as f:
        for line in f:
            m = EVAL_RE.search(line)
            if not m: continue
            ts, ue, _ppo, td, tu, pd, pu, pa, du, dd = m.groups()
            out.append((int(ts), int(ue),
                        float(td), float(tu), float(pd), float(pu),
                        float(pa), float(du), float(dd)))
    return out

def parse_scens(path):
    windows = {}
    with open(path) as f:
        for r in csv.DictReader(f):
            windows.setdefault(r["scenario"], (int(r["start_ms"]), int(r["end_ms"]),
                                                int(r["label"]) if r["ue_pov"]=="0" else None,
                                                None))
            # Capture label per UE
            ue = int(r["ue_pov"]); lbl = int(r["label"])
            st, en, l0, l1 = windows[r["scenario"]]
            if ue == 0: l0 = lbl
            else: l1 = lbl
            windows[r["scenario"]] = (st, en, l0, l1)
    return windows

broad_samples = parse_log("/tmp/eval_ext_log.txt")
broad_wins    = parse_scens("/tmp/eval_ext_scens.csv")
v74_samples   = parse_log("/tmp/eval_v74_log.txt")
v74_wins      = parse_scens("/tmp/eval_v74_scens.csv")

# Prefer v7.4 samples for beacon/lowslow scenarios
def in_window(ts, st, en): return st <= ts <= en

print(f"broad samples: {len(broad_samples)}  v7.4 samples: {len(v74_samples)}")
print(f"broad scenarios: {list(broad_wins.keys())}")

def build_obs_for_scenario(samples, st, en, scenario_name):
    eng = SelfFeatureEngineer()
    by_ts = defaultdict(dict)
    for s in samples:
        ts, ue, td, tu, pd, pu, pa, du, dd = s
        if not in_window(ts, st, en): continue
        by_ts[ts][ue] = (td, tu, pd, pu, pa, du, dd)
    obs_per_ue = defaultdict(list)
    for ts in sorted(by_ts):
        batch = by_ts[ts]
        ues = sorted(batch.keys())
        for ue in ues:
            td, tu, pd, pu, pa, du, dd = batch[ue]
            self_m = {"DRB.UEThpDl":td,"DRB.UEThpUl":tu,
                      "RRU.PrbUsedDl":pd,"RRU.PrbUsedUl":pu,
                      "RRU.PrbAvailDl":pa,
                      "DRB.AirIfDelayUl":du,"DRB.RlcSduDelayDl":dd}
            other_list = []
            for o in ues:
                if o == ue: continue
                t1,t2,p1,p2,pa2,d1,d2 = batch[o]
                other_list.append({"DRB.UEThpDl":t1,"DRB.UEThpUl":t2,
                                   "RRU.PrbUsedDl":p1,"RRU.PrbUsedUl":p2,
                                   "RRU.PrbAvailDl":pa2,
                                   "DRB.AirIfDelayUl":d1,"DRB.RlcSduDelayDl":d2})
            # Build obs — same logic as production
            raw = normalize_raw_nue(td, tu, pd, pu, pa, du, dd)
            # eng.step() returns 11-dim: 5 eng + 3 timing + 3 zscore
            eng_block = eng.step(ue, td, tu, du, pd, pa)
            # population (5) + interaction (4)
            all_thp_dl   = [td] + [o["DRB.UEThpDl"] for o in other_list]
            all_prb_used = [pd] + [o["RRU.PrbUsedDl"] for o in other_list]
            pop   = A.population_features(td, pd, pa, all_thp_dl, all_prb_used)
            inter = A.interaction_nue_features(td, pd, all_thp_dl, all_prb_used)
            obs = np.concatenate([raw, eng_block, pop, inter]).astype(np.float32)
            obs_per_ue[ue].append(obs)
    return obs_per_ue

# Determine which log+window to use per scenario
SCEN_SOURCE = {}
for name in broad_wins:
    SCEN_SOURCE[name] = ("broad", broad_wins[name])
for name in v74_wins:
    if name in ("08_ue1_beacon", "09_ue0_lowslow"):
        SCEN_SOURCE[name] = ("v74", v74_wins[name])

# Build obs vectors per scenario
print("\nReplaying obs vectors...")
all_obs = {}  # {scenario: {ue: np.array(N, 27)}}
for name, (src, win) in SCEN_SOURCE.items():
    st, en, l0, l1 = win
    samples = broad_samples if src == "broad" else v74_samples
    obs_dict = build_obs_for_scenario(samples, st, en, name)
    all_obs[name] = {ue: np.stack(obs_dict[ue]) if obs_dict[ue] else np.zeros((0,OBS_DIM_NUE))
                     for ue in (0,1)}
    n0 = all_obs[name][0].shape[0]; n1 = all_obs[name][1].shape[0]
    print(f"  {name:22s} src={src} N_UE0={n0} N_UE1={n1} labels=({l0},{l1})")

# Build idle baseline (pool all UEs from 01_both_idle)
idle = np.vstack([all_obs["01_both_idle"][0], all_obs["01_both_idle"][1]])
print(f"\nIdle baseline pool: {idle.shape[0]} samples")

# AUC-ROC per (attack_scenario, feature): how well this feature alone
# separates attacker samples from idle samples. 0.5 = no signal, 1.0 = perfect.
def auc_separability(attack, idle):
    """Compute |AUC - 0.5| * 2 ∈ [0, 1].  1.0 = perfect separator."""
    if attack.shape[0] < 5 or idle.shape[0] < 5: return 0.0
    # Mann-Whitney U formulation, robust to ties + zero-std
    combined = np.concatenate([attack, idle])
    n_a, n_i = len(attack), len(idle)
    ranks = combined.argsort().argsort() + 1   # 1-based
    # Tie handling (average ranks for ties)
    order = np.argsort(combined, kind="mergesort")
    sorted_c = combined[order]
    avg_ranks = np.empty_like(ranks, dtype=np.float64)
    i = 0
    while i < len(sorted_c):
        j = i
        while j+1 < len(sorted_c) and sorted_c[j+1] == sorted_c[i]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j+1):
            avg_ranks[order[k]] = avg
        i = j + 1
    R_a = avg_ranks[:n_a].sum()
    U = R_a - n_a * (n_a + 1) / 2
    auc = U / (n_a * n_i)
    return abs(auc - 0.5) * 2.0   # symmetric [0, 1]

# Map scenario → (UE_attacker index, label)
SCEN_ATTACKER = {
    "01_both_idle":      None,            # baseline
    "02_ue0_icmp_flood": 0,
    "03_ue1_light_ddos": 1,
    "04_both_medium":    None,            # benign, skip
    "05_ue0_mining":     0,
    "06_ue1_mining":     1,
    "07_ue0_burst":      0,
    "08_ue1_beacon":     1,
    "09_ue0_lowslow":    0,
    "10_ue1_rampup":     1,
    "11_ue0_exfil":      0,
    "12_both_attack":    "both",          # show separately
}

# Compute |d| matrix: rows=features, cols=attacks
attack_cols = ["02_ue0_icmp_flood","03_ue1_light_ddos","05_ue0_mining","06_ue1_mining",
               "07_ue0_burst","08_ue1_beacon","09_ue0_lowslow","10_ue1_rampup",
               "11_ue0_exfil","12_both_attack"]
col_labels = ["icmp_flood","light_ddos","mining(UE0)","mining(UE1)","burst","beacon",
              "lowslow","rampup","exfil","both_attack"]

mat = np.zeros((OBS_DIM_NUE, len(attack_cols)))
for j, scen in enumerate(attack_cols):
    atk = SCEN_ATTACKER[scen]
    if atk == "both":
        attack_obs = np.vstack([all_obs[scen][0], all_obs[scen][1]])
    elif atk is None:
        continue
    else:
        attack_obs = all_obs[scen][atk]
    if attack_obs.shape[0] < 5: continue
    for i in range(OBS_DIM_NUE):
        mat[i, j] = auc_separability(attack_obs[:, i], idle[:, i])

# Sort features by total importance (sum of |d| across attacks)
total_imp = mat.sum(axis=1)
order = np.argsort(-total_imp)
mat_sorted = mat[order]
names_sorted  = [FEATURE_NAMES[i] for i in order]
groups_sorted = [GROUP_OF[i] for i in order]

fig, ax = plt.subplots(figsize=(13, 11))
im = ax.imshow(mat_sorted, aspect='auto', cmap='YlOrRd', vmin=0, vmax=1.0)
ax.set_xticks(range(len(col_labels)))
ax.set_xticklabels(col_labels, rotation=35, ha='right', fontsize=10)
ax.set_yticks(range(OBS_DIM_NUE))
# Color-code y-tick labels by group
y_labels = []
for n, g in zip(names_sorted, groups_sorted):
    y_labels.append(n)
ax.set_yticklabels(y_labels, fontsize=9)
for i, g in enumerate(groups_sorted):
    ax.get_yticklabels()[i].set_color(GROUP_COLOR[g])

# Annotate cells with |d| value (rounded)
for i in range(mat_sorted.shape[0]):
    for j in range(mat_sorted.shape[1]):
        v = mat_sorted[i, j]
        if v > 0.15:
            ax.text(j, i, f"{v:.2f}", ha="center", va="center",
                    color="black" if v < 0.6 else "white", fontsize=7)

ax.set_title(
    "Per-attack feature importance — production v7.4 27-dim observation\n"
    "Cells = AUC-ROC separability (attacker vs idle baseline); 1.0 = perfect separator",
    fontsize=12)
ax.set_xlabel("Attack scenario (real testbed, ping ICMP)")
ax.set_ylabel("27-dim feature (sorted by total importance across attacks)")

# Legend for groups
import matplotlib.patches as mpatches
handles = [mpatches.Patch(color=c, label=g) for g, c in GROUP_COLOR.items()]
ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(1.18, 1),
          fontsize=9, title="Feature group")
plt.colorbar(im, ax=ax, label="AUC separability (0 = no signal, 1 = perfect)",
             fraction=0.04, pad=0.02)
plt.tight_layout()
out = f"{OUT}/fig_feature_per_attack.png"
plt.savefig(out, dpi=140, bbox_inches="tight")
print(f"\nSaved {out}")

# Also dump top-3 features per attack to console
print("\n Top-3 most-discriminative features per attack (real testbed) ")
for j, (scen, label) in enumerate(zip(attack_cols, col_labels)):
    if mat[:, j].sum() == 0:
        continue
    top = np.argsort(-mat[:, j])[:3]
    feats = ", ".join(f"{FEATURE_NAMES[i]} (AUC-sep={mat[i,j]:.2f})" for i in top)
    print(f"  {label:14s} → {feats}")
