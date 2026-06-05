"""
Calibrate optimal N-of-M and Confidence-weighted thresholds
Run on labeled_real_v1.csv with full pipeline
Find threshold maximizing F1 across all scenarios
"""
import os, sys
import numpy as np
import pandas as pd
from collections import deque
from sklearn.metrics import f1_score, precision_score, recall_score
sys.path.insert(0, "/home/nttrung/my-xapp/src")
os.environ["DRL_MODEL_PATH"] = "/home/nttrung/my-xapp/drl_v7_3_3_nue"
from drl_agent_nue import DrlAgentNue, SelfFeatureEngineer

print("Loading model + data...")
agent = DrlAgentNue()
df = pd.read_csv("/home/nttrung/kpm_data/labeled_real_v1.csv")
df = df.sort_values(["scenario","timestamp"]).reset_index(drop=True)

def metrics(row, ue):
    return {"DRB.UEThpDl":row[f"thp_dl_{ue}"], "DRB.UEThpUl":row[f"thp_ul_{ue}"],
            "RRU.PrbUsedDl":row[f"prb_used_dl_{ue}"], "RRU.PrbUsedUl":row[f"prb_used_ul_{ue}"],
            "RRU.PrbAvailDl":row[f"prb_avail_dl_{ue}"],
            "DRB.AirIfDelayUl":row[f"delay_ul_{ue}"], "DRB.RlcSduDelayDl":row[f"delay_dl_{ue}"]}

# Build per-indication (action, confidence) records per UE per scenario
print("Running pipeline per indication...")
records = {}  # scenario -> list of (idx, ue, action, conf, label)

for scen in sorted(df["scenario"].unique()):
    sub = df[df["scenario"]==scen].reset_index(drop=True)
    agent.feature_engineer = SelfFeatureEngineer()
    agent._active_samples.clear(); agent._migrated_ues.clear(); agent._lowrate_streak.clear()
    
    scen_records = []
    for i, row in sub.iterrows():
        rd = row._asdict() if hasattr(row, '_asdict') else row.to_dict()
        m0, m1 = metrics(rd, 0), metrics(rd, 1)
        obs0 = agent._build_obs(0, m0, [m1])
        obs1 = agent._build_obs(1, m1, [m0])
        a0_arr, _ = agent._model.predict(obs0, deterministic=True)
        a1_arr, _ = agent._model.predict(obs1, deterministic=True)
        a0, a1 = int(a0_arr), int(a1_arr)
        ad = {0:a0, 1:a1}
        md = {0:m0, 1:m1}
        ad = agent._symmetric_suppression(ad, md)
        ad = agent._asymmetric_victim_suppression(ad, md)
        ad = agent._lowrate_asymmetric_promotion(ad, md)
        
        for ue in [0, 1]:
            conf = 0.85 if ad[ue] == 1 else 0.15
            scen_records.append((i, ue, ad[ue], conf, rd[f"label_{ue}"]))
    records[scen] = scen_records

print(f"Done. {sum(len(v) for v in records.values())} total decisions captured")

def apply_accumulator(records, window, vote_n, score_th, conf_th=0.6):
    """Simulate accumulator on captured records, return per-scenario F1."""
    results = {}
    for scen, recs in records.items():
        # Per UE deque
        history = {0: deque(maxlen=window), 1: deque(maxlen=window)}
        triggered = {0: False, 1: False}
        
        # Track predictions per indication post-accumulator
        pred_per_ue = {0: [], 1: []}
        label_per_ue = {0: [], 1: []}
        
        for idx, ue, action, conf, label in recs:
            history[ue].append((action, conf))
            if triggered[ue]:
                # Already triggered → stays as 1
                pred_per_ue[ue].append(1)
            else:
                vote_count = sum(1 for a, c in history[ue] if a==1 and c>=conf_th)
                score = sum(c for a, c in history[ue] if a==1)
                if vote_count >= vote_n or score >= score_th:
                    triggered[ue] = True
                    pred_per_ue[ue].append(1)
                else:
                    pred_per_ue[ue].append(0)
            label_per_ue[ue].append(label)
        
        y_p = pred_per_ue[0] + pred_per_ue[1]
        y_t = label_per_ue[0] + label_per_ue[1]
        if sum(y_t) == 0:
            f1 = float(sum(p==t for p,t in zip(y_p,y_t))/len(y_t))
        else:
            f1 = f1_score(y_t, y_p, zero_division=0)
        results[scen] = (f1, precision_score(y_t, y_p, zero_division=0), recall_score(y_t, y_p, zero_division=0))
    
    # Aggregate F1 (excluding both_attack which is known limitation)
    all_p, all_t = [], []
    for scen, recs in records.items():
        if "ue1_attack_ue0_2M" in scen: continue
        for idx, ue, action, conf, label in recs:
            pass  # rebuild from sim... actually compute again
    # Simpler aggregate
    overall_p, overall_t = [], []
    for scen, recs in records.items():
        if "ue1_attack_ue0_2M" in scen: continue
        history = {0: deque(maxlen=window), 1: deque(maxlen=window)}
        triggered = {0: False, 1: False}
        for idx, ue, action, conf, label in recs:
            history[ue].append((action, conf))
            if triggered[ue]:
                pred = 1
            else:
                vote_count = sum(1 for a, c in history[ue] if a==1 and c>=conf_th)
                score = sum(c for a, c in history[ue] if a==1)
                if vote_count >= vote_n or score >= score_th:
                    triggered[ue] = True
                    pred = 1
                else:
                    pred = 0
            overall_p.append(pred); overall_t.append(label)
    overall_f1 = f1_score(overall_t, overall_p, zero_division=0) if sum(overall_t) > 0 else 0
    return results, overall_f1

# Grid search over (vote_n, score_th)
print("\n=== Grid search for optimal thresholds ===")
print(f"{'window':<8}{'N':<4}{'score_th':<10}{'F1 (excl both_attack)':<25}")
print("-" * 50)

best_f1 = 0
best_params = None
window = 10

for vote_n in [3, 4, 5, 6, 7]:
    for score_th in [2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0]:
        _, f1 = apply_accumulator(records, window, vote_n, score_th)
        marker = ""
        if f1 > best_f1:
            best_f1 = f1
            best_params = (window, vote_n, score_th)
            marker = " ← BEST"
        print(f"{window:<8}{vote_n:<4}{score_th:<10.2f}{f1:.4f}{marker}")

print(f"\n*** BEST: window={best_params[0]}, vote_n={best_params[1]}, score_th={best_params[2]:.2f}, F1={best_f1:.4f} ***")

# Print per-scenario F1 with best params
print(f"\nPer-scenario F1 with best params:")
results, _ = apply_accumulator(records, *best_params)
for scen in sorted(results.keys()):
    f1, p, r = results[scen]
    print(f"  {scen:35s}: F1={f1:.3f}  P={p:.3f}  R={r:.3f}")
