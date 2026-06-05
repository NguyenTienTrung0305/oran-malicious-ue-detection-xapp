import os, sys, pickle
import numpy as np
import pandas as pd
from collections import deque
from sklearn.metrics import f1_score
sys.path.insert(0, "/home/nttrung/my-xapp/src")
os.environ["DRL_MODEL_PATH"] = "/home/nttrung/my-xapp/drl_v7_3_3_nue"
from drl_agent_nue import DrlAgentNue, SelfFeatureEngineer

agent = DrlAgentNue()
df = pd.read_csv("/home/nttrung/kpm_data/labeled_real_v1.csv")
df = df.sort_values(["scenario","timestamp"]).reset_index(drop=True)

def metrics(row, ue):
    return {"DRB.UEThpDl":row[f"thp_dl_{ue}"], "DRB.UEThpUl":row[f"thp_ul_{ue}"],
            "RRU.PrbUsedDl":row[f"prb_used_dl_{ue}"], "RRU.PrbUsedUl":row[f"prb_used_ul_{ue}"],
            "RRU.PrbAvailDl":row[f"prb_avail_dl_{ue}"],
            "DRB.AirIfDelayUl":row[f"delay_ul_{ue}"], "DRB.RlcSduDelayDl":row[f"delay_dl_{ue}"]}

# Build records once
print("Building records...")
records = {}
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
        a0, _ = agent._model.predict(obs0, deterministic=True)
        a1, _ = agent._model.predict(obs1, deterministic=True)
        ad = {0:int(a0), 1:int(a1)}; md = {0:m0, 1:m1}
        ad = agent._symmetric_suppression(ad, md)
        ad = agent._asymmetric_victim_suppression(ad, md)
        ad = agent._lowrate_asymmetric_promotion(ad, md)
        for ue in [0, 1]:
            conf = 0.85 if ad[ue] == 1 else 0.15
            scen_records.append((ue, ad[ue], conf, rd[f"label_{ue}"]))
    records[scen] = scen_records

def sim(window, vote_n, score_th, conf_th=0.6, exclude_both=True):
    overall_p, overall_t = [], []
    for scen, recs in records.items():
        if exclude_both and "ue1_attack_ue0_2M" in scen: continue
        history = {0: deque(maxlen=window), 1: deque(maxlen=window)}
        triggered = {0: False, 1: False}
        for ue, action, conf, label in recs:
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
    return f1_score(overall_t, overall_p, zero_division=0)

# Baseline: current 1-indication trigger
def baseline_1ind():
    overall_p, overall_t = [], []
    for scen, recs in records.items():
        if "ue1_attack_ue0_2M" in scen: continue
        triggered = {0: False, 1: False}
        for ue, action, conf, label in recs:
            if triggered[ue]:
                pred = 1
            elif action == 1 and conf >= 0.6:
                triggered[ue] = True
                pred = 1
            else:
                pred = 0
            overall_p.append(pred); overall_t.append(label)
    return f1_score(overall_t, overall_p, zero_division=0)

print(f"\nBaseline 1-indication trigger: F1 = {baseline_1ind():.4f}")
print("\n=== Grid search (exclude both_attack) ===")
print(f"{'win':<5}{'N':<4}{'score_th':<10}{'F1':<10}")
print("-" * 35)
best = (0, None)
for window in [5, 10, 15, 20]:
    for vote_n in [2, 3, 4, 5]:
        for score_th in [1.5, 2.0, 2.5, 3.0]:
            if vote_n > window: continue
            f1 = sim(window, vote_n, score_th)
            mark = ""
            if f1 > best[0]:
                best = (f1, (window, vote_n, score_th))
                mark = "BEST"
            if f1 >= 0.96:
                print(f"{window:<5}{vote_n:<4}{score_th:<10.2f}{f1:.4f}{mark}")
print(f"\n*** BEST: win={best[1][0]}, N={best[1][1]}, score_th={best[1][2]}, F1={best[0]:.4f} ***")
