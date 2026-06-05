#!/usr/bin/env python3
"""
FOR ONLINE TRAINING, MAY BE DIFFERENT FROM FINAL VERSION USED IN XAPP, LET'S CHECK 
"""

from collections import defaultdict, deque
import numpy as np

try:
    import gymnasium as gym
    from gymnasium import spaces
    HAS_GYM = True
except ImportError:
    try:
        import gym
        from gym import spaces
        HAS_GYM = True
    except ImportError:
        HAS_GYM = False

METRIC_ORDER = [
    "DRB.UEThpDl",                  
    "DRB.UEThpUl",                  
    "RRU.PrbUsedDl",                
    "RRU.PrbUsedUl",                
    "RRU.PrbAvailDl",               
    "DRB.AirIfDelayUl",             
    "DRB.RlcSduDelayDl",            
    "DRB.RlcPacketDropRateDl",      
]

ENGINEERED_NAMES = [
    "util_ratio_dl",
    "ul_dl_ratio",
    "prb_efficiency",
    "burstiness",
    "sustained_count",
    "delay_jitter",
]

OBS_DIM = len(METRIC_ORDER) + len(ENGINEERED_NAMES)  # 14

BOUNDS = {
    "DRB.UEThpDl":              (0.0, 150_000.0),
    "DRB.UEThpUl":              (0.0, 50_000.0),
    "RRU.PrbUsedDl":            (0.0, 106.0),
    "RRU.PrbUsedUl":            (0.0, 106.0),
    "RRU.PrbAvailDl":           (0.0, 106.0),
    "DRB.AirIfDelayUl":         (0.0, 100.0),
    "DRB.RlcSduDelayDl":        (0.0, 500.0),
    "DRB.RlcPacketDropRateDl":  (0.0, 100.0),
}

ENG_BOUNDS = {
    "util_ratio_dl":   (0.0, 1.0),
    "ul_dl_ratio":     (0.0, 5.0),
    "prb_efficiency":  (0.0, 1000.0),
    "burstiness":      (0.0, 3.0),
    "sustained_count": (0.0, 30.0),
    "delay_jitter":    (0.0, 50.0),
}


class FeatureEngineer:

    def __init__(self, window_size=30):
        self.window_size = window_size
        self._history = defaultdict(lambda: deque(maxlen=window_size))

    def compute(self, ue_id, raw_metrics):
        self._history[ue_id].append(dict(raw_metrics))
        hist = self._history[ue_id]
        n = len(hist)

        thp_dl = float(raw_metrics.get('DRB.UEThpDl', 0.0))
        thp_ul = float(raw_metrics.get('DRB.UEThpUl', 0.0))
        prb_used_dl = float(raw_metrics.get('RRU.PrbUsedDl', 0.0))
        prb_avail_dl = float(raw_metrics.get('RRU.PrbAvailDl', 0.0))

        util_ratio = prb_used_dl / max(prb_avail_dl, 1.0)
        ul_dl_ratio = thp_ul / max(thp_dl, 1.0)
        prb_eff = thp_dl / max(prb_used_dl, 1.0)

        if n >= 5:
            thp_dl_ts = [float(h.get('DRB.UEThpDl', 0.0)) for h in hist]
            delay_ts = [float(h.get('DRB.AirIfDelayUl', 0.0)) for h in hist]
            mean_thp = float(np.mean(thp_dl_ts))
            std_thp = float(np.std(thp_dl_ts))
            burstiness = std_thp / max(mean_thp, 1.0)
            p95 = float(np.percentile(thp_dl_ts, 95))
            sustained = sum(1 for t in thp_dl_ts if t > p95 * 0.7)
            delay_jitter = float(np.std(delay_ts))
        else:
            burstiness = 0.0
            sustained = 0.0
            delay_jitter = 0.0

        return {
            "util_ratio_dl":   util_ratio,
            "ul_dl_ratio":     ul_dl_ratio,
            "prb_efficiency":  prb_eff,
            "burstiness":      burstiness,
            "sustained_count": float(sustained),
            "delay_jitter":    delay_jitter,
        }

    def reset(self, ue_id=None):
        if ue_id is None:
            self._history.clear()
        else:
            self._history.pop(ue_id, None)


def normalize_obs(raw_metrics, engineered):
    obs = np.zeros(OBS_DIM, dtype=np.float32)
    for i, name in enumerate(METRIC_ORDER):
        val = float(raw_metrics.get(name, 0.0))
        lo, hi = BOUNDS[name]
        if hi - lo > 1e-9:
            obs[i] = np.clip((val - lo) / (hi - lo), 0.0, 1.0)
    for j, name in enumerate(ENGINEERED_NAMES):
        val = float(engineered.get(name, 0.0))
        lo, hi = ENG_BOUNDS[name]
        if hi - lo > 1e-9:
            obs[len(METRIC_ORDER) + j] = np.clip((val - lo) / (hi - lo), 0.0, 1.0)
    return obs


UE_PROFILES = {
    "normal_idle": {
        "is_malicious": False,
        "metrics": {
            "DRB.UEThpDl":              (0, 0),
            "DRB.UEThpUl":              (0, 0),
            "RRU.PrbUsedDl":            (0, 0),
            "RRU.PrbUsedUl":            (0, 0),
            "RRU.PrbAvailDl":           (51, 0),
            "DRB.AirIfDelayUl":         (0, 0),
            "DRB.RlcSduDelayDl":        (0, 0),
            "DRB.RlcPacketDropRateDl":  (0, 0),
        },
    },
    "normal_browsing": {
        "is_malicious": False,
        "metrics": {
            "DRB.UEThpDl":              (15_000, 8_000),
            "DRB.UEThpUl":              (2_000, 1_500),
            "RRU.PrbUsedDl":            (15, 8),
            "RRU.PrbUsedUl":            (5, 3),
            "RRU.PrbAvailDl":           (51, 0),
            "DRB.AirIfDelayUl":         (5, 3),
            "DRB.RlcSduDelayDl":        (8, 4),
            "DRB.RlcPacketDropRateDl":  (0.5, 0.5),
        },
    },
    "normal_streaming": {
        "is_malicious": False,
        "metrics": {
            "DRB.UEThpDl":              (50_000, 15_000),
            "DRB.UEThpUl":              (1_000, 500),
            "RRU.PrbUsedDl":            (40, 15),
            "RRU.PrbUsedUl":            (3, 2),
            "RRU.PrbAvailDl":           (51, 0),
            "DRB.AirIfDelayUl":         (3, 2),
            "DRB.RlcSduDelayDl":        (5, 3),
            "DRB.RlcPacketDropRateDl":  (0.2, 0.3),
        },
    },
    "normal_voip": {
        "is_malicious": False,
        "metrics": {
            "DRB.UEThpDl":              (500, 200),
            "DRB.UEThpUl":              (500, 200),
            "RRU.PrbUsedDl":            (3, 2),
            "RRU.PrbUsedUl":            (3, 2),
            "RRU.PrbAvailDl":           (51, 0),
            "DRB.AirIfDelayUl":         (15, 5),
            "DRB.RlcSduDelayDl":        (15, 5),
            "DRB.RlcPacketDropRateDl":  (1.0, 1.0),
        },
    },
    "malicious_ddos_ul": {
        "is_malicious": True,
        "metrics": {
            "DRB.UEThpDl":              (5_000, 3_000),
            "DRB.UEThpUl":              (40_000, 10_000),    # UL flood
            "RRU.PrbUsedDl":            (10, 5),
            "RRU.PrbUsedUl":            (80, 20),            # PRB hog UL
            "RRU.PrbAvailDl":           (51, 0),
            "DRB.AirIfDelayUl":         (30, 15),
            "DRB.RlcSduDelayDl":        (30, 15),
            "DRB.RlcPacketDropRateDl":  (35, 15),
        },
    },
    "malicious_ddos_dl": {
        "is_malicious": True,
        "metrics": {
            "DRB.UEThpDl":              (120_000, 20_000),   # DL flood
            "DRB.UEThpUl":              (35_000, 10_000),
            "RRU.PrbUsedDl":            (90, 15),            # PRB hog DL
            "RRU.PrbUsedUl":            (85, 15),
            "RRU.PrbAvailDl":           (51, 0),
            "DRB.AirIfDelayUl":         (8, 5),
            "DRB.RlcSduDelayDl":        (10, 5),
            "DRB.RlcPacketDropRateDl":  (5, 3),
        },
    },
    "malicious_exfil": {
        "is_malicious": True,
        "metrics": {
            "DRB.UEThpDl":              (2_000, 1_000),      # Low DL
            "DRB.UEThpUl":              (30_000, 8_000),     # High UL
            "RRU.PrbUsedDl":            (5, 3),
            "RRU.PrbUsedUl":            (60, 20),
            "RRU.PrbAvailDl":           (51, 0),
            "DRB.AirIfDelayUl":         (10, 5),
            "DRB.RlcSduDelayDl":        (10, 5),
            "DRB.RlcPacketDropRateDl":  (2, 2),
        },
    },
    "malicious_mining": {
        "is_malicious": True,
        "metrics": {
            "DRB.UEThpDl":              (2_000, 200),        # Low jitter
            "DRB.UEThpUl":              (1_800, 200),        # UL/DL ≈ 1
            "RRU.PrbUsedDl":            (5, 1),
            "RRU.PrbUsedUl":            (5, 1),
            "RRU.PrbAvailDl":           (51, 0),
            "DRB.AirIfDelayUl":         (8, 2),
            "DRB.RlcSduDelayDl":        (10, 3),
            "DRB.RlcPacketDropRateDl":  (0.5, 0.3),
        },
    },
    "malicious_slowloris": {
        "is_malicious": True,
        "metrics": {
            "DRB.UEThpDl":              (200, 100),
            "DRB.UEThpUl":              (100, 50),
            "RRU.PrbUsedDl":            (20, 10),
            "RRU.PrbUsedUl":            (25, 12),
            "RRU.PrbAvailDl":           (51, 0),
            "DRB.AirIfDelayUl":         (60, 20),            # High latency
            "DRB.RlcSduDelayDl":        (80, 30),
            "DRB.RlcPacketDropRateDl":  (15, 10),
        },
    },
}

PROFILE_WEIGHTS = {
    "normal_idle":          0.10,
    "normal_browsing":      0.20,
    "normal_streaming":     0.15,
    "normal_voip":          0.10,
    "malicious_ddos_ul":    0.10,
    "malicious_ddos_dl":    0.10,
    "malicious_exfil":      0.10,
    "malicious_mining":     0.08,
    "malicious_slowloris":  0.07,
}


def _sample_profile(profile_name, rng=None):
    rng = rng or np.random
    profile = UE_PROFILES[profile_name]
    metrics = {}
    for name in METRIC_ORDER:
        mean, std = profile["metrics"][name]
        val = max(0.0, rng.normal(mean, std))
        metrics[name] = val
    return metrics, profile["is_malicious"]


if HAS_GYM:
    class MaliciousUeDetectionEnv(gym.Env):
        metadata = {"render_modes": ["human"]}

        def __init__(self, episode_length=200, switch_prob=0.05):
            super().__init__()
            self.episode_length = episode_length
            self.switch_prob = switch_prob
            self.observation_space = spaces.Box(
                low=0.0, high=1.0, shape=(OBS_DIM,), dtype=np.float32
            )
            self.action_space = spaces.Discrete(2)
            self._engineer = FeatureEngineer(window_size=30)
            self._profile_names = list(UE_PROFILES.keys())
            self._weights = np.array(
                [PROFILE_WEIGHTS[p] for p in self._profile_names]
            )
            self._weights /= self._weights.sum()
            self._current_profile = None
            self._step_count = 0
            self._correct_streak = 0

        def reset(self, seed=None, options=None):
            super().reset(seed=seed)
            self._engineer.reset(ue_id="ue0")
            self._current_profile = self.np_random.choice(
                self._profile_names, p=self._weights
            )
            self._step_count = 0
            self._correct_streak = 0
            obs = self._get_obs()
            return obs, {"profile": self._current_profile}

        def step(self, action):
            self._step_count += 1
            is_malicious = UE_PROFILES[self._current_profile]["is_malicious"]

            if action == 1 and is_malicious:
                reward = 1.0
                self._correct_streak += 1
            elif action == 0 and not is_malicious:
                reward = 0.5
                self._correct_streak += 1
            elif action == 1 and not is_malicious:
                reward = -2.0
                self._correct_streak = 0
            else:
                reward = -1.0
                self._correct_streak = 0

            if self._correct_streak > 10:
                reward += 0.1

            if self.np_random.random() < self.switch_prob:
                self._current_profile = self.np_random.choice(
                    self._profile_names, p=self._weights
                )
                self._engineer.reset(ue_id="ue0")

            terminated = self._step_count >= self.episode_length
            obs = self._get_obs()
            info = {
                "profile": self._current_profile,
                "is_malicious": is_malicious,
                "correct": (action == 1) == is_malicious,
            }
            return obs, reward, terminated, False, info

        def _get_obs(self):
            metrics, _ = _sample_profile(self._current_profile, self.np_random)
            engineered = self._engineer.compute("ue0", metrics)
            return normalize_obs(metrics, engineered)


    class ReplayCsvEnv(gym.Env):
        metadata = {"render_modes": ["human"]}

        def __init__(self, csv_path, episode_length=200, shuffle=True):
            super().__init__()
            try:
                import pandas as pd
            except ImportError:
                raise ImportError("pandas required for ReplayCsvEnv")
            self.df = pd.read_csv(csv_path)
            assert "is_malicious" in self.df.columns, "CSV must have 'is_malicious' label"
            self.episode_length = episode_length
            self.shuffle = shuffle

            self.observation_space = spaces.Box(
                low=0.0, high=1.0, shape=(OBS_DIM,), dtype=np.float32
            )
            self.action_space = spaces.Discrete(2)
            self._engineer = FeatureEngineer(window_size=30)

            # Group by ue_id để giữ tính time-continuity của history window
            self._ue_groups = list(self.df.groupby("ue_id"))
            self._step_count = 0
            self._correct_streak = 0
            self._current_idx = 0
            self._current_ue_data = None

        def _pick_episode_data(self):
            ue_id, ue_df = self._ue_groups[
                self.np_random.integers(0, len(self._ue_groups))
            ]
            if self.shuffle and len(ue_df) > self.episode_length:
                start = self.np_random.integers(
                    0, len(ue_df) - self.episode_length
                )
                ue_df = ue_df.iloc[start:start + self.episode_length]
            self._current_ue_data = ue_df.reset_index(drop=True)
            self._current_idx = 0

        def reset(self, seed=None, options=None):
            super().reset(seed=seed)
            self._engineer.reset()
            self._step_count = 0
            self._correct_streak = 0
            self._pick_episode_data()
            return self._get_obs(), {}

        def step(self, action):
            self._step_count += 1
            row = self._current_ue_data.iloc[self._current_idx]
            is_malicious = bool(row["is_malicious"])

            if action == 1 and is_malicious:
                reward = 1.0
                self._correct_streak += 1
            elif action == 0 and not is_malicious:
                reward = 0.5
                self._correct_streak += 1
            elif action == 1 and not is_malicious:
                reward = -2.0
                self._correct_streak = 0
            else:
                reward = -1.0
                self._correct_streak = 0

            if self._correct_streak > 10:
                reward += 0.1

            self._current_idx += 1
            terminated = (
                self._current_idx >= len(self._current_ue_data) or
                self._step_count >= self.episode_length
            )
            obs = self._get_obs() if not terminated else np.zeros(OBS_DIM, dtype=np.float32)
            info = {"is_malicious": is_malicious, "correct": (action == 1) == is_malicious}
            return obs, reward, terminated, False, info

        def _get_obs(self):
            row = self._current_ue_data.iloc[self._current_idx]
            metrics = {name: float(row[name]) for name in METRIC_ORDER}
            ue_id = int(row["ue_id"])
            engineered = self._engineer.compute(ue_id, metrics)
            return normalize_obs(metrics, engineered)
else:
    MaliciousUeDetectionEnv = None
    ReplayCsvEnv = None


def generate_dataset(n_samples=10000, seed=None):
    rng = np.random.RandomState(seed)
    profile_names = list(UE_PROFILES.keys())
    weights = np.array([PROFILE_WEIGHTS[p] for p in profile_names])
    weights /= weights.sum()

    X = np.zeros((n_samples, OBS_DIM), dtype=np.float32)
    y = np.zeros(n_samples, dtype=np.int32)
    engineer = FeatureEngineer(window_size=30)
    current_profile = rng.choice(profile_names, p=weights)
    ue_counter = 0

    for i in range(n_samples):

        if rng.random() < 0.05:
            current_profile = rng.choice(profile_names, p=weights)
            ue_counter += 1
            engineer.reset(ue_id=ue_counter)
        metrics, is_mal = _sample_profile(current_profile, rng)
        engineered = engineer.compute(ue_counter, metrics)
        X[i] = normalize_obs(metrics, engineered)
        y[i] = int(is_mal)

    return X, y

