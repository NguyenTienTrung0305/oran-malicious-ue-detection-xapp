import os, json, time
from collections import deque
import numpy as np
import pandas as pd
import gymnasium as gym
from gymnasium import spaces
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.callbacks import EvalCallback
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CSV_PATH        = os.environ.get("CSV_PATH",
    "/kaggle/input/datasets/stttrrrun/oran-kpm-malicious-ue-v4/labeled_v4.csv")
OUT_DIR         = os.environ.get("OUT_DIR", "/kaggle/working")
TOTAL_TIMESTEPS = int(os.environ.get("TIMESTEPS", "200000"))
WINDOW_SIZE     = int(os.environ.get("WINDOW_SIZE", "150"))
EPISODE_LENGTH  = int(os.environ.get("EPISODE_LENGTH", "350"))
WARMUP_STEPS    = int(os.environ.get("WARMUP_STEPS", "30"))
EPS_MARGIN_THP  = float(os.environ.get("EPS_MARGIN_THP", "100.0"))
EPS_MARGIN_PRB  = float(os.environ.get("EPS_MARGIN_PRB", "0.5"))
EWMA_ALPHA      = float(os.environ.get("EWMA_ALPHA", "0.1"))

OBS_DIM = 27
os.makedirs(OUT_DIR, exist_ok=True)
print(f"[Config] CSV={CSV_PATH}")
print(f"[Config] OBS_DIM={OBS_DIM} (7 raw + 5 eng + 3 timing + 5 pop + 4 inter + 3 zscore-self)")
print(f"[Config] TIMESTEPS={TOTAL_TIMESTEPS}  EWMA_ALPHA={EWMA_ALPHA}")

df = pd.read_csv(CSV_PATH)
print(f"\n[Data] {len(df)} rows")
df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
n_val = int(len(df) * 0.2)
val_df = df.iloc[:n_val].copy()
train_df = df.iloc[n_val:].copy()
print(f"[Data] train: {len(train_df)} | val: {len(val_df)}")
train_csv = os.path.join(OUT_DIR, "train_v7_3_2.csv")
val_csv   = os.path.join(OUT_DIR, "val_v7_3_2.csv")
train_df.to_csv(train_csv, index=False)
val_df.to_csv(val_csv, index=False)


class EwmaTracker:
    def __init__(self, alpha=EWMA_ALPHA, min_samples=5, eps=1.0):
        self.alpha = alpha
        self.min_samples = min_samples
        self.eps = eps
        self.reset()

    def reset(self):
        self.mean = 0.0
        self.var = 0.0
        self.n = 0

    def update(self, x):
        x = float(x)
        if self.n == 0:
            self.mean = x; self.var = 0.0
        else:
            old_mean = self.mean
            self.mean = (1 - self.alpha) * self.mean + self.alpha * x
            self.var = (1 - self.alpha) * (self.var + self.alpha * (x - old_mean) ** 2)
        self.n += 1

    def zscore(self, x):
        if self.n < self.min_samples:
            return 0.0
        z = (float(x) - self.mean) / max(np.sqrt(self.var + self.eps), 1.0)
        return float(np.clip(z, -5.0, 5.0))


class SelfFeatureEngineer:
    """Window-based features + 3 EWMA trackers per UE (z-score self)"""
    def __init__(self, window=WINDOW_SIZE):
        self.w = window
        self.reset()

    def reset(self):
        self.thp_dl = deque(maxlen=self.w)
        self.delay  = deque(maxlen=self.w)
        self._ewma_thp_dl = EwmaTracker()
        self._ewma_prb    = EwmaTracker()
        self._ewma_delay  = EwmaTracker()

    def step(self, thp_dl, thp_ul, delay_ul, prb_used, prb_avail):
        self.thp_dl.append(thp_dl)
        self.delay.append(delay_ul)
        td = np.array(self.thp_dl, dtype=np.float32) if self.thp_dl else np.array([0.0], np.float32)

        # 5 engineered
        util_ratio   = min(prb_used / max(prb_avail, 1), 1.0)
        ul_dl_ratio  = min(thp_ul / max(thp_dl, 1) / 5.0, 1.0)
        prb_eff      = min(thp_dl / max(prb_used, 1) / 1e6, 1.0)
        burstiness   = min(float(td.std()) / max(float(td.mean()), 1) / 3.0, 1.0)
        delay_jitter = min(float(np.std(self.delay)) / 1e5, 1.0) if len(self.delay) > 1 else 0.0

        # 3 timing
        nonzero_ratio = float((td > 0).sum()) / max(len(td), 1)
        peak_to_mean  = float(td.max()) / max(float(td.mean()), 1)
        zero_mask = (td == 0).astype(np.int8)
        transitions = float((zero_mask[1:] != zero_mask[:-1]).sum()) if len(zero_mask) > 1 else 0.0
        zero_runs = transitions / max(len(td), 1)

        # 3 EWMA z-score self (compute BEFORE update — measure vs past)
        z_thp_dl = self._ewma_thp_dl.zscore(thp_dl)
        z_prb    = self._ewma_prb.zscore(prb_used)
        z_delay  = self._ewma_delay.zscore(delay_ul)
        self._ewma_thp_dl.update(thp_dl)
        self._ewma_prb.update(prb_used)
        self._ewma_delay.update(delay_ul)

        eng_timing_z = np.array([
            util_ratio, ul_dl_ratio, prb_eff, burstiness, delay_jitter,
            nonzero_ratio, np.tanh(peak_to_mean / 10.0), zero_runs,
            z_thp_dl / 5.0, z_prb / 5.0, z_delay / 5.0,  # normalize [-1,1]
        ], dtype=np.float32)
        return eng_timing_z  # 11-dim (5 eng + 3 timing + 3 zscore)


def normalize_raw(thp_dl, thp_ul, prb_used_dl, prb_used_ul, prb_avail_dl, delay_ul, delay_dl):
    return np.array([
        min(thp_dl/1e8, 1.0), min(thp_ul/1e8, 1.0),
        min(prb_used_dl/275.0, 1.0), min(prb_used_ul/275.0, 1.0),
        min(prb_avail_dl/275.0, 1.0),
        min(delay_ul/1e6, 1.0), min(delay_dl/1e6, 1.0),
    ], dtype=np.float32)


def gini_array(values):
    v = np.sort(np.abs(np.asarray(values, dtype=np.float64)))
    n = len(v)
    if n == 0 or v.sum() < 1e-9: return 0.0
    cum = np.cumsum(v)
    return float((n + 1 - 2*(cum.sum()/cum[-1]))/n)


def population_features(thp_dl_self, prb_used_self, prb_avail_self,
                         all_thp_dl, all_prb_used):
    all_thp = np.asarray(all_thp_dl, dtype=np.float64)
    all_prb = np.asarray(all_prb_used, dtype=np.float64)
    sum_prb = all_prb.sum()
    return np.array([
        prb_used_self / max(sum_prb, 1.0),
        float(np.tanh((thp_dl_self - all_thp.mean()) / max(all_thp.std(), 1.0))),
        float(np.tanh((prb_used_self - all_prb.mean()) / max(all_prb.std(), 0.5))),
        min(sum_prb / max(prb_avail_self, 1.0), 2.0) / 2.0,
        gini_array(all_thp),
    ], dtype=np.float32)


def interaction_nue_features(thp_dl_self, prb_used_self, all_thp_dl, all_prb_used):
    all_thp = np.asarray(all_thp_dl, dtype=np.float64)
    all_prb = np.asarray(all_prb_used, dtype=np.float64)
    others_thp = np.array([t for t in all_thp if t != thp_dl_self] or [0.0])
    others_prb = np.array([p for p in all_prb if p != prb_used_self] or [0.0])
    max_o_thp = float(others_thp.max())
    max_o_prb = float(others_prb.max())
    is_top_prb = 1.0 if prb_used_self > max_o_prb + EPS_MARGIN_PRB else 0.0
    is_top_thp = 1.0 if thp_dl_self  > max_o_thp + EPS_MARGIN_THP else 0.0
    victim_signal = max(0.0, (max_o_thp - thp_dl_self) / max(max_o_thp, 1.0))
    dominance = (thp_dl_self - float(all_thp.mean())) / max(float(all_thp.sum()), 1.0)
    return np.array([is_top_prb, is_top_thp, victim_signal, dominance], dtype=np.float32)


def build_obs(thp_dl_s, thp_ul_s, prb_used_dl_s, prb_used_ul_s, prb_avail_dl_s,
              delay_ul_s, delay_dl_s, all_thp_dl, all_prb_used, eng_self):
    raw = normalize_raw(thp_dl_s, thp_ul_s, prb_used_dl_s, prb_used_ul_s,
                        prb_avail_dl_s, delay_ul_s, delay_dl_s)
    eng_timing_z = eng_self.step(thp_dl_s, thp_ul_s, delay_ul_s, prb_used_dl_s, prb_avail_dl_s)
    pop = population_features(thp_dl_s, prb_used_dl_s, prb_avail_dl_s, all_thp_dl, all_prb_used)
    inter = interaction_nue_features(thp_dl_s, prb_used_dl_s, all_thp_dl, all_prb_used)
    obs = np.concatenate([raw, eng_timing_z, pop, inter]).astype(np.float32)
    assert obs.shape == (OBS_DIM,), f"obs.shape={obs.shape}"
    return obs


class NUEEnvV732(gym.Env):
    metadata = {"render_modes": ["human"]}
    def __init__(self, csv_path, episode_length=EPISODE_LENGTH, shuffle=True):
        super().__init__()
        self.df = pd.read_csv(csv_path)
        self.episode_length = episode_length
        self.shuffle = shuffle
        self.observation_space = spaces.Box(-1.0, 1.0, (OBS_DIM,), np.float32)
        self.action_space = spaces.Discrete(2)
        self._eng = SelfFeatureEngineer(WINDOW_SIZE)
        
        self._pos, self._neg = [], []
        for scen, g in self.df.groupby("scenario"):
            g_sorted = g.sort_values("timestamp").reset_index(drop=True)
            for ue_pov in [0, 1]:
                lbl = int(g_sorted[f"label_{ue_pov}"].iloc[0])
                (self._pos if lbl == 1 else self._neg).append((scen, ue_pov, g_sorted))
        print(f"[Env] {len(self._pos)} pos + {len(self._neg)} neg groups")
        
        self._data = None 
        self._ue_pov = 0 
        self._idx = 0
        self._step = 0

    # Gọi mỗi khi env.reset() - khởi tạo 1 episode mới
    def _pick(self):
        # Chọn pool 50/50 balance
        pool = self._pos if self.np_random.random() < 0.5 else self._neg
        
        # Chọn ngẫu nhiên 1 scenario + UE POV từ pool
        scen, ue_pov, g = pool[self.np_random.integers(0, len(pool))]
        
        if self.shuffle and len(g) > self.episode_length:
            s = self.np_random.integers(0, len(g) - self.episode_length)
            g = g.iloc[s:s+self.episode_length]
        self._data = g.reset_index(drop=True)
        
        self._ue_pov = ue_pov 
        self._idx = 0 
        self._scen = scen

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self._eng.reset() 
        self._step = 0 
        self._pick()
        return self._get_obs(), {}

    # Convert raw KPM metrics thành feature vector mà PPO model hiểu
    def _get_obs(self):
        if self._idx >= len(self._data):
            return np.zeros(OBS_DIM, dtype=np.float32)
        
        r = self._data.iloc[self._idx]
        sfx_s = "_0" if self._ue_pov==0 else "_1"
        sfx_o = "_1" if self._ue_pov==0 else "_0"
        
        thp_dl_s=float(r[f"thp_dl{sfx_s}"])
        thp_ul_s=float(r[f"thp_ul{sfx_s}"])
        
        prb_used_dl_s=float(r[f"prb_used_dl{sfx_s}"])
        prb_used_ul_s=float(r[f"prb_used_ul{sfx_s}"])
        
        prb_avail_dl_s=float(r[f"prb_avail_dl{sfx_s}"])
        
        delay_ul_s=float(r[f"delay_ul{sfx_s}"])
        delay_dl_s=float(r[f"delay_dl{sfx_s}"])
        
        thp_dl_o=float(r[f"thp_dl{sfx_o}"])
        prb_used_dl_o=float(r[f"prb_used_dl{sfx_o}"])
        
        return build_obs(thp_dl_s, thp_ul_s, prb_used_dl_s, prb_used_ul_s,
                         prb_avail_dl_s, delay_ul_s, delay_dl_s,
                         [thp_dl_s, thp_dl_o], [prb_used_dl_s, prb_used_dl_o], self._eng)

    def step(self, action):
        self._step += 1
        row = self._data.iloc[self._idx]
        label = int(row[f"label_{self._ue_pov}"])
        
        sfx = "_0" if self._ue_pov==0 else "_1"
        
        thp_dl=float(row[f"thp_dl{sfx}"])
        thp_ul=float(row[f"thp_ul{sfx}"])
        prb_used = float(row[f"prb_used_dl{sfx}"]) + float(row[f"prb_used_ul{sfx}"])
        
        is_idle = (thp_dl + thp_ul + prb_used) < 1.0
        
        if self._step <= WARMUP_STEPS: 
            r = 0.0
        elif action == 1 and label == 1: 
            r = 2.0
        elif action == 0 and label == 0: 
            r = 2.0
        elif action == 1 and label == 0: 
            r = -5.0 if is_idle else -3.0
        else: 
            r = -2.0
            
        self._idx += 1
        term = self._idx >= len(self._data) or self._step >= self.episode_length
        obs = self._get_obs() if not term else np.zeros(OBS_DIM, dtype=np.float32)
        return obs, r, term, False, {"is_malicious": label, "ue_pov": self._ue_pov}


train_env = DummyVecEnv([lambda: NUEEnvV732(train_csv, shuffle=True)])
val_env   = DummyVecEnv([lambda: NUEEnvV732(val_csv, shuffle=True)])


model = PPO(
    "MlpPolicy", 
    train_env, 
    verbose=1,
    n_steps=2048,           # (rollout buffer size) collect 2048 step trước mỗi update 
    batch_size=64,          # Chia rollout thành batch 64
    n_epochs=10,            # Mỗi rollout train 10 epoch
    learning_rate=1e-4,     # Tốc độ học
    ent_coef=0.05,          # Hệ số entropy để khuyến khích khám phá, càng cao càng khuyến khích khám phá
    vf_coef=0.25,           # Trọng số loss critic, giúp model học cân bằng giữa học actor vs học critic
    gamma=0.99,             # Trọng số reward tương lai, gần 1.0 có nghĩa là agent quan tâm đến phần thưởng xa hơn trong tương lai
    gae_lambda=0.95,        
    clip_range=0.2,         # giới hạn policy update trong 1 PPO update step
    target_kl=0.02,         # Dừng update nếu KL divergence > 0.02
    max_grad_norm=0.5,      
    policy_kwargs=dict(net_arch=[128, 128]),
    tensorboard_log=os.path.join(OUT_DIR, "tb"), device="cuda")

# callback đánh giá model định kỳ trong khi train
eval_cb = EvalCallback(val_env,
    best_model_save_path=os.path.join(OUT_DIR, "best"),
    log_path=os.path.join(OUT_DIR, "eval"),
    eval_freq=10000, n_eval_episodes=20, deterministic=True, render=False)

t0 = time.time()
model.learn(total_timesteps=TOTAL_TIMESTEPS, callback=eval_cb)
print(f"[Train] elapsed: {time.time()-t0:.0f}s")
model.save(os.path.join(OUT_DIR, "drl_v7_3_2_nue.zip"))

# Eval
print("\n[Eval] Loading BEST")
best = os.path.join(OUT_DIR, "best", "best_model.zip")
eval_model = PPO.load(best, device="cuda") if os.path.exists(best) else model

per_scen = {}
overall_tp=overall_fp=overall_fn=overall_tn=0
val_sorted = val_df.sort_values(["scenario", "timestamp"]).reset_index(drop=True)
for scen in val_sorted["scenario"].unique():
    grp = val_sorted[val_sorted["scenario"]==scen].reset_index(drop=True)
    if len(grp) == 0: 
        continue
    for ue_pov in [0, 1]:
        eng = SelfFeatureEngineer(WINDOW_SIZE)
        tp=fp=fn=tn=0
        sfx_s = "_0" if ue_pov==0 else "_1"
        sfx_o = "_1" if ue_pov==0 else "_0"
        
        for step_i in range(len(grp)):
            r = grp.iloc[step_i]
            thp_dl_s=float(r[f"thp_dl{sfx_s}"])
            thp_ul_s=float(r[f"thp_ul{sfx_s}"])
            
            prb_used_dl_s=float(r[f"prb_used_dl{sfx_s}"])
            prb_used_ul_s=float(r[f"prb_used_ul{sfx_s}"])
            
            prb_avail_dl_s=float(r[f"prb_avail_dl{sfx_s}"])
            
            delay_ul_s=float(r[f"delay_ul{sfx_s}"])
            delay_dl_s=float(r[f"delay_dl{sfx_s}"])
            
            thp_dl_o=float(r[f"thp_dl{sfx_o}"])
            prb_used_dl_o=float(r[f"prb_used_dl{sfx_o}"])
            
            obs = build_obs(thp_dl_s, thp_ul_s, prb_used_dl_s, prb_used_ul_s,
                            prb_avail_dl_s, delay_ul_s, delay_dl_s,
                            [thp_dl_s, thp_dl_o], [prb_used_dl_s, prb_used_dl_o], eng)
            
            if step_i < WARMUP_STEPS: 
                continue
            action, _ = eval_model.predict(obs, deterministic=True)
            a = int(action)
            m = int(r[f"label_{ue_pov}"])
            if a==1 and m==1: tp+=1
            elif a==1 and m==0: fp+=1
            elif a==0 and m==1: fn+=1
            else: tn+=1
        f1 = 2*tp/max(2*tp+fp+fn, 1)
        per_scen[f"{scen}_ue{ue_pov}"] = (f1, tp, fp, fn, tn)
        overall_tp+=tp
        overall_fp+=fp
        overall_fn+=fn
        overall_tn+=tn

P = overall_tp/max(overall_tp+overall_fp, 1)
R = overall_tp/max(overall_tp+overall_fn, 1)
F1 = 2*P*R/max(P+R, 1e-9)
ACC = (overall_tp+overall_tn)/max(overall_tp+overall_fp+overall_fn+overall_tn, 1)
print(f"\n[Eval] OVERALL: P={P:.3f} R={R:.3f} F1={F1:.3f} ACC={ACC:.3f}")
print(f"[Eval] TP={overall_tp} FP={overall_fp} FN={overall_fn} TN={overall_tn}")
print("[Eval] Per-scenario:")
for k,(f1,tp,fp,fn,tn) in sorted(per_scen.items()):
    print(f"  {k:42s} F1={f1:.2f} (TP={tp} FP={fp} FN={fn} TN={tn})")

with open(os.path.join(OUT_DIR, "eval_metrics.json"), "w") as f:
    json.dump({"version":"v7.3.2-nue", "obs_dim":OBS_DIM,
        "overall":{"P":P,"R":R,"F1":F1,"ACC":ACC},
        "per_scenario":{k:{"F1":f1,"TP":tp,"FP":fp,"FN":fn,"TN":tn}
                        for k,(f1,tp,fp,fn,tn) in per_scen.items()}}, f, indent=2)

print(f"\n=== DONE V7.3.2 ===  F1={F1:.3f}")
print(f"OBS_DIM={OBS_DIM} (24-dim v7.3.1 + 3 z-score self EWMA, all N-invariant)")
