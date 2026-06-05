#!/usr/bin/env python3
import logging
import os
from collections import defaultdict, deque

import numpy as np

logger = logging.getLogger("drl_agent_nue")

METRIC_ORDER = [
    "DRB.UEThpDl", "DRB.UEThpUl",
    "RRU.PrbUsedDl", "RRU.PrbUsedUl", "RRU.PrbAvailDl",
    "DRB.AirIfDelayUl", "DRB.RlcSduDelayDl", 
]


OBS_DIM_NUE = 27
WINDOW_SIZE = 150
EPS_MARGIN_THP = 100.0
EPS_MARGIN_PRB = 0.5
EWMA_ALPHA = 0.1


def normalize_raw_nue(thp_dl, thp_ul, prb_used_dl, prb_used_ul,
                      prb_avail_dl, delay_ul, delay_dl):
    return np.array([
        min(thp_dl / 1e8, 1.0),
        min(thp_ul / 1e8, 1.0),
        min(prb_used_dl / 275.0, 1.0),
        min(prb_used_ul / 275.0, 1.0),
        min(prb_avail_dl / 275.0, 1.0),
        min(delay_ul / 1e6, 1.0),
        min(delay_dl / 1e6, 1.0),
    ], dtype=np.float32)


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
            self.mean = x 
            self.var = 0.0
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
    def __init__(self, window=WINDOW_SIZE):
        self.w = window
        self._thp_dl = defaultdict(lambda: deque(maxlen=self.w))
        self._delay  = defaultdict(lambda: deque(maxlen=self.w))
        self._ewma   = defaultdict(lambda: {
            "thp_dl": EwmaTracker(), 
            "prb": EwmaTracker(), 
            "delay": EwmaTracker(),
        })

    def reset_ue(self, ue_id):
        if ue_id in self._thp_dl: 
            self._thp_dl[ue_id].clear()
        if ue_id in self._delay:  
            self._delay[ue_id].clear()
        if ue_id in self._ewma:
            for tr in self._ewma[ue_id].values(): 
                tr.reset()

    def step(self, ue_id, thp_dl, thp_ul, delay_ul, prb_used, prb_avail):
        self._thp_dl[ue_id].append(thp_dl)
        self._delay[ue_id].append(delay_ul)
        td = np.array(self._thp_dl[ue_id], dtype=np.float32) \
             if self._thp_dl[ue_id] else np.array([0.0], np.float32)

        # Tỷ lệ PRB đã dùng / PRB available. Gần 1.0 = cell đang nghẽn
        # Attacker thường đẩy util_ratio cao bất thường khi UE khác vẫn idle
        util_ratio   = min(prb_used / max(prb_avail, 1), 1.0)
        
        # Mất cân đối uplink/downlink. Chia 5.0 vì UL bình thường << DL (web/video), nếu UL lớn gấp 5 lần DL -> chắc chắn malicious 
        # UL > DL nhiều = dấu hiệu exfiltration, beacon, hoặc DDoS
        ul_dl_ratio  = min(thp_ul / max(thp_dl, 1) / 5.0, 1.0)
        
        # Hiệu suất truyền: bao nhiêu bps trên mỗi PRB. Chia 1e6 (1 Mbps = 1e6 bps)
        # Thấp = UE chiếm PRB nhưng truyền ít (lowslow DDoS, mining, beacon)
        prb_eff      = min(thp_dl / max(prb_used, 1) / 1e6, 1.0)
        
        # Độ lệch của throughput
        # Vì traffic bình thường có std/mean ≤ 3. Cao = bursty (flood, scan)
        burstiness   = min(float(td.std()) / max(float(td.mean()), 1) / 3.0, 1.0)
        
        # Dao động delay (jitter). Đổi từ ns sang microsecond (chia 1e3), tiếp theo so với ngưỡng 100 microsecond  (lớn hơn 100 microsecond thì chắc chắn có vấn đề)
        # Cao = network bị congest do attacker, hoặc UE bị retransmit nhiều
        delay_jitter = min(float(np.std(self._delay[ue_id])) / 1e5, 1.0) \
                       if len(self._delay[ue_id]) > 1 else 0.0

        # 3 timing
        # Tỷ lệ sample có truyền dữ liệu
        nonzero_ratio = float((td > 0).sum()) / max(len(td), 1)
        
        # Đỉnh so với trung bình
        peak_to_mean  = float(td.max()) / max(float(td.mean()), 1)
        
        # Số lần chuyển trạng thái (idle sang active và ngược lại )/độ dài buffer -> bắt beacon rất tốt
        zero_mask = (td == 0).astype(np.int8)
        transitions = float((zero_mask[1:] != zero_mask[:-1]).sum()) if len(zero_mask) > 1 else 0.0
        zero_runs = transitions / max(len(td), 1)

        # 3 EWMA z-score self (compute BEFORE update — measure vs past)
        e = self._ewma[ue_id]
        z_thp_dl = e["thp_dl"].zscore(thp_dl)
        z_prb    = e["prb"].zscore(prb_used)
        z_delay  = e["delay"].zscore(delay_ul)
        e["thp_dl"].update(thp_dl)
        e["prb"].update(prb_used)
        e["delay"].update(delay_ul)

        return np.array([
            util_ratio, ul_dl_ratio, prb_eff, burstiness, delay_jitter,
            nonzero_ratio, np.tanh(peak_to_mean / 10.0), zero_runs,
            z_thp_dl / 5.0, z_prb / 5.0, z_delay / 5.0,
        ], dtype=np.float32)


# Gini Coefficient: Đo lường mức độ bất bình đẳng, mức độ chênh lệch dữ liệu trong tập dữ liệu
def gini_array(values):
    v = np.sort(np.abs(np.asarray(values, dtype=np.float64)))
    n = len(v)
    if n == 0 or v.sum() < 1e-9:
        return 0.0
    cum = np.cumsum(v)
    return float((n + 1 - 2 * (cum.sum() / cum[-1])) / n)


def population_features(thp_dl_self, prb_used_self, prb_avail_self,
                         all_thp_dl, all_prb_used):
    """
    all_thp_dl: throughput of all ue in an interval (t)
    all_prb_used: prb used of all ue in an interval (t)
    """
    all_thp = np.asarray(all_thp_dl, dtype=np.float64)
    all_prb = np.asarray(all_prb_used, dtype=np.float64)
    sum_prb  = all_prb.sum()
    mean_thp = all_thp.mean()
    mean_prb = all_prb.mean()
    std_thp  = max(float(all_thp.std()), 1.0)
    std_prb  = max(float(all_prb.std()), 0.5)

    prb_share  = prb_used_self / max(sum_prb, 1.0)
    thp_zscore = float(np.tanh((thp_dl_self - mean_thp) / std_thp))
    prb_zscore = float(np.tanh((prb_used_self - mean_prb) / std_prb))
    total_load = min(sum_prb / max(prb_avail_self, 1.0), 2.0) / 2.0
    thp_gini   = gini_array(all_thp)
    return np.array([prb_share, thp_zscore, prb_zscore, total_load, thp_gini],
                    dtype=np.float32)


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
    
    sum_thp = float(all_thp.sum())
    dominance = (thp_dl_self - float(all_thp.mean())) / max(sum_thp, 1.0)
    return np.array([is_top_prb, is_top_thp, victim_signal, dominance], dtype=np.float32)


class DrlAgentNue:
    def __init__(self, model_path=None):
        self.model_path = model_path or os.environ.get(
            "DRL_MODEL_PATH", "/tmp/drl_model"
        )
        self.feature_engineer = SelfFeatureEngineer(WINDOW_SIZE)
        self._model = None
        self._model_loaded = False
        self._try_load_model()
        self._history = deque(maxlen=500)
        self._stats = {"total_decisions": 0, "quarantine_decisions": 0,
                       "allow_decisions": 0, "warmup_decisions": 0}
        
        self._active_samples = defaultdict(int)
        self._migrated_ues = set()
        
        # lowrate-asymmetric promotion: streak counter per UE
        self._lowrate_streak = defaultdict(int)

    def _try_load_model(self):
        try:
            import sys, numpy
            if not hasattr(numpy, "_core"):
                sys.modules["numpy._core"] = numpy.core
                sys.modules["numpy._core.multiarray"] = numpy.core.multiarray
                sys.modules["numpy._core.numeric"] = numpy.core.numeric
                sys.modules["numpy._core._dtype_ctypes"] = getattr(
                    numpy.core, "_dtype_ctypes", numpy.core
                )
            from stable_baselines3 import PPO
            model_file = self.model_path + ".zip"
            if os.path.exists(model_file):
                self._model = PPO.load(self.model_path, device="cpu")
                self._model_loaded = True
                logger.info("Loaded PPO model (obs=%s)",
                            self._model.observation_space.shape)
                print(f"[DRL] Loaded — obs={self._model.observation_space.shape}")
            else:
                logger.info("No pre-trained model at %s", model_file)
        except Exception as e:
            logger.error("Model load failed: %s", e, exc_info=True)


    # Build obs 
    def _build_obs(self, ue_id, self_metrics, all_other_metrics_list):
        """
        Args:
          ue_id: identifier for self
          self_metrics: dict KPM metrics of self
          all_other_metrics_list: list of dict, all OTHER UEs' metrics
                                  (empty list -> degenerate to self-only population)
        Returns: np.ndarray(22,) in [0, 1]
        """
        # Self values
        thp_dl_s   = float(self_metrics.get("DRB.UEThpDl", 0))
        thp_ul_s   = float(self_metrics.get("DRB.UEThpUl", 0))
        prb_dl_s   = float(self_metrics.get("RRU.PrbUsedDl", 0))
        prb_ul_s   = float(self_metrics.get("RRU.PrbUsedUl", 0))
        prb_avail  = float(self_metrics.get("RRU.PrbAvailDl", 0))
        delay_ul_s = float(self_metrics.get("DRB.AirIfDelayUl", 0))
        delay_dl_s = float(self_metrics.get("DRB.RlcSduDelayDl", 0))

        # Population: self + all others
        all_thp_dl  = [thp_dl_s] + [float(m.get("DRB.UEThpDl", 0)) for m in all_other_metrics_list]
        all_prb_used = [prb_dl_s] + [float(m.get("RRU.PrbUsedDl", 0)) for m in all_other_metrics_list]

        raw = normalize_raw_nue(thp_dl_s, thp_ul_s, prb_dl_s, prb_ul_s,
                                prb_avail, delay_ul_s, delay_dl_s)
        
        eng_timing = self.feature_engineer.step(
            ue_id, thp_dl_s, thp_ul_s, delay_ul_s, prb_dl_s, prb_avail
        )
        
        pop = population_features(thp_dl_s, prb_dl_s, prb_avail,
                                  all_thp_dl, all_prb_used)
        
        inter = interaction_nue_features(thp_dl_s, prb_dl_s, all_thp_dl, all_prb_used)

        obs = np.concatenate([raw, eng_timing, pop, inter]).astype(np.float32)
        assert obs.shape == (OBS_DIM_NUE,), f"obs.shape={obs.shape}"
        return obs

    """
    Nếu 2+ UE bị PPO flag malicious đồng thời nhưng load của họ symmetric và load không quá cao => ovveride về false
    => Do bug hàm interaction_nue_features, Vì cả 2 cùng is_top_thp=1 (do bug filter equality), dominance xấp xỉ 0, signature lạ 
        => model flag oan. Rule này patch hậu
    """
    def _symmetric_suppression(self, actions, ue_metrics_dict,
                                symmetry_threshold=0.30, attack_thp_kbps=3000):
        flagged = [ue for ue, a in actions.items() if a == 1]
        if len(flagged) < 2:
            return actions
        totals = {
            ue: float(ue_metrics_dict[ue].get("DRB.UEThpDl", 0)) + float(ue_metrics_dict[ue].get("DRB.UEThpUl", 0)) 
            for ue in flagged
            }
        
        # Throughput cao nhất trong các UE flagged
        # Nếu mọi UE flagged đều có throughput < 1 => rule không xử lý (tránh chia cho 0 ở dòng tiếp)
        # Trường hợp này xảy ra khi: tất cả UE flagged đều idle nhưng vẫn bị PPO flag (rare, do bug filter equality làm features lạ)
        max_r = max(totals.values())
        if max_r < 1: 
            return actions
        
        # Đo độ symmetric
        min_r = min(totals.values())
        symmetry = (max_r - min_r) / max_r
        
        if symmetry < symmetry_threshold and max_r < attack_thp_kbps:
            return {ue: (0 if a == 1 else a) for ue, a in actions.items()}
        return actions

    # Phát hiện attack rate cực thấp (beacon, lowslow) mà PPO model bỏ sót (thường loại attack này có delay_dl rất cao)
    def _lowrate_asymmetric_promotion(self, actions, ue_metrics_dict,
                                       streak_min=30, signal_eps=0.5):
        def _signal(m):
            return (float(m.get("DRB.UEThpDl", 0))
                  + float(m.get("DRB.UEThpUl", 0))
                  + float(m.get("DRB.AirIfDelayUl", 0))
                  + float(m.get("DRB.RlcSduDelayDl", 0)))

        new_actions = dict(actions)
        for ue, a in actions.items():
            self_sig = _signal(ue_metrics_dict[ue])
            others_sig = sum(_signal(ue_metrics_dict[u])
                             for u in ue_metrics_dict if u != ue)
            cond = (self_sig > signal_eps) and (others_sig <= signal_eps)
            if cond:
                self._lowrate_streak[ue] += 1
            else:
                self._lowrate_streak[ue] = 0
            if a == 0 and self._lowrate_streak[ue] >= streak_min:
                new_actions[ue] = 1
                logger.info("[v7.4 lowrate_rule] UE=%s promote 0→1 "
                            "(self_sig=%.2f, others_sig=%.2f, streak=%d)",
                            ue, self_sig, others_sig, self._lowrate_streak[ue])
        return new_actions

    def _asymmetric_victim_suppression(self, actions, ue_metrics_dict,
                                        victim_th=0.7, dom_th=-0.3):
        if not any(a == 1 for a in actions.values()):
            return actions
        # Gather thp_dl for population
        all_thp = {ue: float(ue_metrics_dict[ue].get("DRB.UEThpDl", 0))
                   for ue in actions.keys()}
        mean_thp = sum(all_thp.values()) / max(len(all_thp), 1)
        sum_thp = sum(all_thp.values())
        new_actions = dict(actions)
        for ue, a in actions.items():
            if a != 1: continue
            self_thp = all_thp[ue]
            others = [t for u, t in all_thp.items() if u != ue]
            max_o = max(others) if others else 0.0
            victim_signal = max(0.0, (max_o - self_thp) / max(max_o, 1.0))
            dominance = (self_thp - mean_thp) / max(sum_thp, 1.0)
            if victim_signal > victim_th and dominance < dom_th:
                new_actions[ue] = 0
                logger.info("[v7.3.3 victim_rule] UE=%s override flag->0 "
                            "(victim=%.2f, dom=%.2f)", ue, victim_signal, dominance)
        return new_actions


    def _is_idle(self, metrics):
        return (float(metrics.get("DRB.UEThpDl", 0))
              + float(metrics.get("DRB.UEThpUl", 0))
              + float(metrics.get("RRU.PrbUsedDl", 0))) < 1.0


    def decide_batch(self, ue_metrics_dict, warmup_min=30):
        """
        Batch-decide actions for all UEs in current indication.

        Returns dict {ue_id: action in {0, 1}}.
        """
        ue_ids = list(ue_metrics_dict.keys())

        # Idle-skip: nếu MỌI UE đều idle -> trả về toàn 0, skip predict
        if all(self._is_idle(ue_metrics_dict[u]) for u in ue_ids):
            return {u: (0, 0.0, "idle") for u in ue_ids}

        results = {}
        confidences = {}

        for ue_id in ue_ids:
            self_m = ue_metrics_dict[ue_id]
            # Update active counter
            if not self._is_idle(self_m):
                self._active_samples[ue_id] += 1

            others = [ue_metrics_dict[u] for u in ue_ids if u != ue_id]

            try:
                obs = self._build_obs(ue_id, self_m, others)
            except Exception as e:
                logger.warning("Build obs failed UE=%s: %s", ue_id, e)
                results[ue_id] = 0
                confidences[ue_id] = 0.0
                continue

            if self._model_loaded and self._model is not None:
                try:
                    import torch
                    obs_t = torch.as_tensor(obs, dtype=torch.float32).unsqueeze(0)
                    with torch.no_grad():
                        dist = self._model.policy.get_distribution(obs_t)
                        probs = dist.distribution.probs.cpu().numpy().flatten()
                    action = int(np.argmax(probs))
                    real_conf = float(probs[action])
                except Exception as e:
                    logger.warning("get_distribution failed UE=%s: %s", ue_id, e)
                    action, _ = self._model.predict(obs, deterministic=True)
                    action = int(action)
                    real_conf = 0.85 if action == 1 else 0.15
            else:
                action = 0
                real_conf = 1.0

            # Warmup gate: chưa đủ active samples -> no flag
            if action == 1 and self._active_samples[ue_id] < warmup_min:
                action = 0
                self._stats["warmup_decisions"] += 1

            # Dedup: đã migrate rồi -> skip
            if action == 1 and ue_id in self._migrated_ues:
                action = 0

            results[ue_id] = action
            confidences[ue_id] = real_conf

        results = self._symmetric_suppression(results, ue_metrics_dict)
        results = self._asymmetric_victim_suppression(results, ue_metrics_dict)
        results = self._lowrate_asymmetric_promotion(results, ue_metrics_dict)

        # Convert {ue: int} -> {ue: (action, confidence, reason)} for xapp.py compat
        tuple_results = {}
        for u, a in results.items():
            conf = confidences.get(u, 0.5)
            reason = "PPO+rules"
            tuple_results[u] = (a, conf, reason)
            self._stats["total_decisions"] += 1
            if a == 1: 
                self._stats["quarantine_decisions"] += 1
            else: 
                self._stats["allow_decisions"] += 1
            self._history.append((u, a))
        return tuple_results


    def mark_migrated(self, ue_id):
        self._migrated_ues.add(ue_id)

    def mark_released(self, ue_id):
        self._migrated_ues.discard(ue_id)
        self._active_samples[ue_id] = 0
        self.feature_engineer.reset_ue(ue_id)

    def get_stats(self):
        return dict(self._stats)

    def eval_predict_raw(self, ue_metrics_dict):
        results = {}
        ue_ids = list(ue_metrics_dict.keys())
        for ue_id in ue_ids:
            self_m = ue_metrics_dict[ue_id]
            others = [ue_metrics_dict[u] for u in ue_ids if u != ue_id]
            try:
                obs = self._build_obs(ue_id, self_m, others)
                if self._model_loaded and self._model is not None:
                    action_arr, _ = self._model.predict(obs, deterministic=True)
                    results[ue_id] = (int(action_arr), obs)
                else:
                    results[ue_id] = (0, obs)
            except Exception as e:
                logger.warning("eval_predict_raw failed UE=%s: %s", ue_id, e)
                results[ue_id] = (-1, None)

        actions = {ue: a for ue, (a, _) in results.items() if a != -1}
        actions = self._symmetric_suppression(actions, ue_metrics_dict)
        actions = self._asymmetric_victim_suppression(actions, ue_metrics_dict)
        actions = self._lowrate_asymmetric_promotion(actions, ue_metrics_dict)
        for ue, new_a in actions.items():
            if results[ue][0] != new_a:
                results[ue] = (new_a, results[ue][1])
        return results
