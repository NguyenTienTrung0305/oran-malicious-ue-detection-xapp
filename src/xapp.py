#!/usr/bin/env python3
"""
KPM Monitor + DRL Malicious-UE Detection xApp.

Lifecycle:
  1. RMR ready -> post_init
  2. Register với AppMgr -> RTMGR tạo routes
  3. Wait cho routes ổn định
  4. Discover gNBs qua E2 Manager
  5. Subscribe KPM metrics qua SubMgr
  6. Nhận RIC Indication -> decode E2AP -> decode KPM -> feed DRL
  7. DRL quyết định -> RC Controller enforce slicing
  8. Graceful shutdown -> unsubscribe all
"""

import os
import signal
import time
import json
import csv
import threading
import http.server
import urllib.parse
from mdclogpy import Logger
from ricxappframe.xapp_frame import RMRXapp, rmr

from asn1_codec import (
    encode_kpm_event_trigger,
    encode_kpm_action_definition,
    decode_e2ap_indication,
    decode_kpm_indication,
    get_metrics_for_group,
    KPM_OID,
    DRL_METRICS,
    SRSRAN_KPM_METRICS,
)

from submgr_client import SubscriptionManager
from gnb_discovery import GnbDiscovery
from rc_controller import RcController
from drl_agent_nue import DrlAgentNue as DrlAgent

logger = Logger(name=__name__)
logger.set_level(3)

XAPP_NAME       = os.environ.get("XAPP_NAME", "my-xapp")
METRIC_GROUP    = os.environ.get("KPM_METRIC_GROUP", "drl_malicious_ue")
REPORT_PERIOD   = int(os.environ.get("KPM_REPORT_PERIOD_MS", "1024"))       # Tần suất gNB GỬI indication xuống xApp (qua mạng)
GRANULARITY_MS  = int(os.environ.get("KPM_GRANULARITY_MS", "1000"))         # Tần suất gNB ĐO metric trong nội bộ (sample rate)
KPM_STYLE       = int(os.environ.get("KPM_STYLE", "5"))  # 1=cell, 3=per-UE-cond, 5=per-UE-all-metrics
KPM_UE_IDS      = os.environ.get("KPM_UE_IDS", "0,1")    # F1AP IDs cho Style 5
DRL_ENABLED     = os.environ.get("DRL_ENABLED", "true").lower() == "true"
DRL_MODEL_PATH  = os.environ.get("DRL_MODEL_PATH", "/tmp/drl_model")
GNB_WAIT_TIMEOUT = int(os.environ.get("GNB_WAIT_TIMEOUT", "120"))
ROUTE_WAIT_SECS = int(os.environ.get("ROUTE_WAIT_SECS", "60"))
TEST_CONTROL_ON_STARTUP = os.environ.get("TEST_CONTROL_ON_STARTUP", "0") == "1"
TEST_CONTROL_DELAY_S    = int(os.environ.get("TEST_CONTROL_DELAY_S", "15"))
TEST_CONTROL_UE_ID      = int(os.environ.get("TEST_CONTROL_UE_ID", "0"))

# Data collection cho DRL training — Phase B
DATA_LOG_ENABLED  = os.environ.get("DATA_LOG_ENABLED", "0") == "1"
DATA_LOG_PATH     = os.environ.get("DATA_LOG_PATH", "/tmp/kpm_log.csv")

# RMR message types
RIC_SUB_REQ      = 12010
RIC_SUB_RESP     = 12011
RIC_SUB_FAILURE  = 12012
RIC_SUB_DEL_RESP = 12021
RIC_INDICATION   = 12050
RIC_CONTROL_REQ  = 12040
RIC_CONTROL_ACK  = 12041
RIC_CONTROL_FAIL = 12042


class MyXapp:
    def __init__(self):
        self._name = XAPP_NAME
        self._submgr = None
        self._rc = None
        self._drl = None
        self._discovery = GnbDiscovery()
        self._gnb_info = {}            # meid -> GnbInfo
        self._subscribed_metrics = []  # metric names đang subscribe
        self._indication_count = 0
        self._migrated_ues = set()     # (meid, ue_id) đã quarantine — tránh spam Control
        self._drl_active_samples = {}  # (meid, ue_id) -> count of non-idle indications seen


        from collections import deque as _deque
        self._accum_window = 5         # M = 5 indications
        self._accum_vote_n = 3         # N = 3 (>=60% majority)
        self._accum_conf_th = 0.6      # per-indication conf threshold
        self._accum_score_th = 2.0     # confidence-sum threshold
        self._accum_history = {}       # (meid, ue_id) -> deque[(action, conf)]
        self._accum_deque_cls = _deque

        # CSV logger cho data collection Phase B
        self._csv_file = None
        self._csv_writer = None
        self._csv_lock = threading.Lock()
        if DATA_LOG_ENABLED:
            self._init_csv_logger()

        # Create RMRXapp
        self._xapp = RMRXapp(
            default_handler=self._default_handler,
            config_handler=self._config_handler,
            rmr_port=4560,
            post_init=self._post_init,
            use_fake_sdl=False,
        )

        # fallback - RMR nhận về 1 message, framework xem msg type trong header rồi tra register_callback().
        # Nếu msg_type trùng 1 trong 6 cái dưới -> framework gọi callback tương ứng, nếu không trùng -> gọi default_handler 
        self._xapp.register_callback(self._on_indication,    RIC_INDICATION)
        self._xapp.register_callback(self._on_sub_resp,      RIC_SUB_RESP)
        self._xapp.register_callback(self._on_sub_failure,   RIC_SUB_FAILURE)
        self._xapp.register_callback(self._on_sub_del_resp,  RIC_SUB_DEL_RESP)
        self._xapp.register_callback(self._on_control_ack,   RIC_CONTROL_ACK)
        self._xapp.register_callback(self._on_control_fail,  RIC_CONTROL_FAIL)

        # Signal handlers
        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)


    # --- CSV Data Logger (DRL data collection)
    def _init_csv_logger(self):
        """
        Khởi tạo CSV writer cho data collection
        """
        try:
            os.makedirs(os.path.dirname(DATA_LOG_PATH), exist_ok=True)
            new_file = not os.path.exists(DATA_LOG_PATH)
            self._csv_file = open(DATA_LOG_PATH, "a", buffering=1, newline="")
            self._csv_writer = csv.writer(self._csv_file)
            if new_file:
                self._csv_writer.writerow([
                    "timestamp", "meid", "ue_id",
                    "DRB.UEThpDl", "DRB.UEThpUl",
                    "RRU.PrbUsedDl", "RRU.PrbUsedUl", "RRU.PrbAvailDl",
                    "DRB.AirIfDelayUl", "DRB.RlcSduDelayDl",
                    "DRB.RlcPacketDropRateDl",
                ])
            print(f"[DataLog] CSV logging enabled -> {DATA_LOG_PATH}")
        except Exception as e:
            logger.error(f"[DataLog] Failed to init CSV: {e}")
            self._csv_file = None
            self._csv_writer = None

    def _log_to_csv(self, meid, ue_id, metrics):
        if self._csv_writer is None:
            return
        try:
            with self._csv_lock:
                self._csv_writer.writerow([
                    int(time.time() * 1000),  # ms epoch
                    meid, ue_id,
                    metrics.get("DRB.UEThpDl", 0),
                    metrics.get("DRB.UEThpUl", 0),
                    metrics.get("RRU.PrbUsedDl", 0),
                    metrics.get("RRU.PrbUsedUl", 0),
                    metrics.get("RRU.PrbAvailDl", 0),
                    metrics.get("DRB.AirIfDelayUl", 0),
                    metrics.get("DRB.RlcSduDelayDl", 0),
                    metrics.get("DRB.RlcPacketDropRateDl", 0),
                ])
        except Exception as e:
            logger.error(f"[DataLog] Write failed: {e}")


    def _post_init(self, xapp):
        """
            - Callback sau khi RMR ready
            - Sau khi RMR ready (mở SCTP port, connect SDL, load RMR route tables) -> gọi _post_init() để xApp có thể bắt đầu subscribe, discover
        """
        print("[Main] RMR READY!")

        # 1. Tạo SubMgr Client ( cần xapp.sdl để persist subscription state — nếu xApp restart, sub không bị mất)
        self._submgr = SubscriptionManager(
            xapp_name=self._name,
            xapp_ip=f"service-ricxapp-{self._name}-http.ricxapp",
            sdl_client=xapp.sdl,
        )
        
        # 2. Tạo RC Controller
        self._rc = RcController(xapp_rmr=xapp)

        # 3. Load DRL model
        if DRL_ENABLED:
            self._drl = DrlAgent(model_path=DRL_MODEL_PATH)
            print("[Main] DRL Agent enabled (heuristic warmup)")
        else:
            print("[Main] DRL Agent disabled")

        
        # 4. Register với AppMgr (HTTP) -> kích RTMGR tạo route
        self._register_with_appmgr()
        print(f"[Main] Waiting {ROUTE_WAIT_SECS}s for RTMGR routes...")    # Wait cho RTMGR tạo routes
        time.sleep(ROUTE_WAIT_SECS)

        # 5. Discover gNB + subscribe KPM
        self._subscribe_all()

        # Start periodic stats (background)
        stats_thread = threading.Thread(target=self._periodic_stats, daemon=True)
        stats_thread.start()

        # Start manual HTTP trigger => release quarantine UE
        self._start_migrate_http(port=int(os.environ.get("MIGRATE_HTTP_PORT", "8081")))

        # Test control, gửi RIC Control Request giả để test end to end ( Chỉ dùng khi debug )
        if TEST_CONTROL_ON_STARTUP and self._gnb_info:
            first_meid = next(iter(self._gnb_info.keys()))
            t = threading.Thread(
                target=self._send_test_control, args=(first_meid,), daemon=True
            )
            t.start()


    def _register_with_appmgr(self):
        """
            Register xApp với AppMgr để RTMGR tạo RMR routes
        """
        import requests
        appmgr_url = os.environ.get(
            "SERVICE_RICPLT_APPMGR_HTTP",
            "http://service-ricplt-appmgr-http.ricplt:8080",
        )

        config_path = os.environ.get("CONFIG_FILE", "/config/config-file.json")
        try:
            with open(config_path) as f:
                config_data = f.read()
        except Exception:
            config_data = "{}"

        print("[Main] Registering with AppMgr...")
        for attempt in range(10):
            try:
                resp = requests.post(
                    f"{appmgr_url}/ric/v1/register",
                    json={
                        "appName": self._name,
                        "appVersion": "1.0.1",
                        "configPath": "",
                        "appInstanceName": self._name,
                        "httpEndpoint": f"service-ricxapp-{self._name}-http.ricxapp:8080",
                        "rmrEndpoint": f"service-ricxapp-{self._name}-rmr.ricxapp:4560",
                        "config": config_data,
                    },
                    timeout=10,
                )
                if resp.status_code in (200, 201):
                    print(f"[Main] Registration OK (attempt {attempt + 1})")
                    return
                else:
                    print(f"[Main] Register attempt {attempt + 1}: {resp.status_code}")
            except Exception as e:
                print(f"[Main] Register attempt {attempt + 1} error: {e}")
            time.sleep(2)

        print("[Main] WARNING: AppMgr registration failed after 10 attempts")


    # --- Subscription
    def _subscribe_all(self):
        """
            Discover KPM gNBs và subscribe
        """
        
        # Lấy metric list
        try:
            metric_names = get_metrics_for_group(METRIC_GROUP)
        except ValueError:
            print(f"[Main] Unknown group '{METRIC_GROUP}', using all metrics")
            metric_names = list(SRSRAN_KPM_METRICS)

        self._subscribed_metrics = metric_names

        # Discover gNBs
        gnb = self._discovery.wait_for_gnb(timeout_s=GNB_WAIT_TIMEOUT)
        if gnb is None:
            print("[Main] No KPM-capable gNB found!")
            return

        self._gnb_info[gnb.inventory_name] = gnb

        print(
            f"[Main] Subscribing to {len(metric_names)} metrics on "
            f"{gnb.inventory_name} (func_id={gnb.kpm_ran_function_id})"
        )

        # Encode ASN.1 payloads — Style 5 (multi-UE, all metrics per-UE) preferred
        ev_trig = encode_kpm_event_trigger(period_ms=REPORT_PERIOD)
        style = KPM_STYLE
        ue_ids_list = [int(x) for x in KPM_UE_IDS.split(",") if x.strip()]
        act_def = encode_kpm_action_definition(
            metric_names=metric_names,
            granularity_ms=GRANULARITY_MS,
            style=style,
            ue_ids=ue_ids_list,
        )
        if not act_def and style == 5:
            print("[Main] Style 5 encode failed, falling back to Style 3")
            style = 3
            act_def = encode_kpm_action_definition(
                metric_names=metric_names,
                granularity_ms=GRANULARITY_MS,
                style=3,
                ue_ids=ue_ids_list,
            )
        if not act_def and style == 3:
            print("[Main] Style 3 encode failed, falling back to Style 1")
            style = 1
            act_def = encode_kpm_action_definition(
                metric_names=metric_names,
                granularity_ms=GRANULARITY_MS,
                style=1,
            )

        if not ev_trig or not act_def:
            print("[Main] ASN.1 encoding failed!")
            return

        style_label = {1: "cell-level", 3: "per-UE-cond", 5: "per-UE-all"}.get(style, "?")
        print(f"[Main] Using KPM Style {style} ({style_label}) ue_ids={ue_ids_list}")

        # Subscribe
        self._submgr.subscribe(
            meid=gnb.inventory_name,
            ran_function_id=gnb.kpm_ran_function_id,
            event_trigger_bytes=ev_trig,
            action_def_bytes=act_def,
            metric_names=metric_names,
        )

        print("[Main] Subscription request sent!")


    # --- RMR Message Handlers
    def _on_indication(self, xapp, summary, sbuf):
        """
            RIC_INDICATION -> decode E2AP -> decode KPM -> DRL -> RC
        """
        try:
            self._indication_count += 1
            raw = summary.get(rmr.RMR_MS_PAYLOAD, b"")
            meid = (
                summary.get(rmr.RMR_MS_MEID, b"")
                .decode(errors="ignore").strip("\x00")
            )

            # Step 1: Decode outer E2AP
            e2ap = decode_e2ap_indication(raw)
            if not e2ap:
                if self._indication_count % 500 == 0:
                    print(f"[Indication] E2AP decode failed from {meid} (count={self._indication_count})")
                return

            # Step 2: Decode inner E2SM-KPM
            metric_names = (
                self._submgr.get_metric_names()
                if self._submgr
                else self._subscribed_metrics
            )

            kpm = decode_kpm_indication(
                e2ap.get("indication_header", b""),
                e2ap.get("indication_message", b""),
                metric_names=metric_names,
            )

            ue_list = kpm.get("ue_list", [])
            if not ue_list:
                return

            # CSV data logging 
            if self._csv_writer is not None:
                for uid, metrics in ue_list:
                    self._log_to_csv(meid, uid, metrics)

            # Log mỗi 10 indications — tất cả UEs
            if self._indication_count % 10 == 0:
                for uid, metrics in ue_list:
                    thp_dl = metrics.get("DRB.UEThpDl", 0)
                    thp_ul = metrics.get("DRB.UEThpUl", 0)
                    prb_dl = metrics.get("RRU.PrbUsedDl", 0)
                    print(
                        f"[Indication] #{self._indication_count} "
                        f"UE={uid} from {meid}: "
                        f"DRB.UEThpDl={thp_dl}, DRB.UEThpUl={thp_ul}, "
                        f"RRU.PrbUsedDl={prb_dl} | "
                        + ", ".join(f"{k}={v}" for k, v in metrics.items()
                                    if k not in ("DRB.UEThpDl", "DRB.UEThpUl", "RRU.PrbUsedDl"))
                    )

            if self._drl:
                ue_metrics_dict = {uid: metrics for uid, metrics in ue_list}
                self._drl_decide_batch(meid, ue_metrics_dict)

        except Exception as e:
            logger.error(f"[Indication] Exception: {e}")
        finally:
            xapp.rmr_free(sbuf)

    # decision logic
    def _drl_decide_batch(self, meid, ue_metrics_dict):
        
        # GUARD 1: idle skip - nếu tất cả UEs đều idle (thp+PRB = 0) thì skip không cần gọi DRL, cũng không cần count warmup samples
        any_active = False
        for m in ue_metrics_dict.values():
            if (float(m.get("DRB.UEThpDl", 0)) + float(m.get("DRB.UEThpUl", 0))
                    + float(m.get("RRU.PrbUsedDl", 0)) + float(m.get("RRU.PrbUsedUl", 0))) > 0:
                any_active = True
                break
        if not any_active:
            return

        
        decisions = self._drl.decide_batch(ue_metrics_dict)

        for ue_id, (action, confidence, reason) in decisions.items():
            # Per-UE warmup: chỉ count khi UE này thực sự active (Thp+PRB > 0)
            m = ue_metrics_dict.get(ue_id, {})
            ue_active = (float(m.get("DRB.UEThpDl", 0)) + float(m.get("DRB.UEThpUl", 0))
                         + float(m.get("RRU.PrbUsedDl", 0)) + float(m.get("RRU.PrbUsedUl", 0))) > 0
            wkey = (meid, int(ue_id))
            
            if ue_active:
                self._drl_active_samples[wkey] = self._drl_active_samples.get(wkey, 0) + 1
            if self._drl_active_samples.get(wkey, 0) < 30:
                continue

            key = (meid, int(ue_id))
            if key in self._migrated_ues:
                continue

            # Accumulator: track every decision in sliding window
            if key not in self._accum_history:
                self._accum_history[key] = self._accum_deque_cls(maxlen=self._accum_window)
            self._accum_history[key].append((action, float(confidence)))

            # Check 2 trigger conditions (OR):
            vote_count = sum(
                1 for a, c in self._accum_history[key]
                if a == 1 and c >= self._accum_conf_th
            )
            weighted_score = sum(
                c for a, c in self._accum_history[key] if a == 1
            )
            vote_pass = vote_count >= self._accum_vote_n
            score_pass = weighted_score >= self._accum_score_th

            if vote_pass or score_pass:
                trigger_reason = []
                if vote_pass: 
                    trigger_reason.append(f"vote={vote_count}/{self._accum_window}")
                if score_pass: 
                    trigger_reason.append(f"score={weighted_score:.2f}")
                print(
                    f"[DRL V5] UE {ue_id} flagged MALICIOUS "
                    f"(conf={confidence:.2f}, reason={reason}, "
                    f"accumulator={'+'.join(trigger_reason)}) -> auto-migrate"
                )
                # EVAL_MODE=1: log full pipeline decision, skip migrate
                if os.environ.get("DRL_EVAL_MODE", "0") == "1":
                    self._migrated_ues.add(key)
                    continue

                # Production mode: actual migrate via RIC Control
                gnb_info = self._gnb_info.get(meid)
                if gnb_info and self._rc:
                    try:
                        self._rc.set_slice_prb_quota(
                            meid=meid,
                            slice_name="quarantine",
                            ue_id=int(ue_id),
                            ran_function_id=gnb_info.rc_ran_function_id,
                        )
                        self._migrated_ues.add(key)
                    except Exception as e:
                        logger.error(f"[DRL V5] Migrate failed UE={ue_id}: {e}")
            else:
                # Suspect but not yet triggered — log debug, continue accumulating
                if action == 1 and confidence > 0.6:
                    logger.debug(
                        f"[V5] UE {ue_id} suspect: vote={vote_count}/{self._accum_window}, "
                        f"score={weighted_score:.2f} (need vote>={self._accum_vote_n} or score>={self._accum_score_th})"
                    )
                continue


    def _on_sub_resp(self, xapp, summary, sbuf):
        meid = summary.get(rmr.RMR_MS_MEID, b"").decode(errors="ignore")
        print(f"[Sub] RESP from {meid} — subscription confirmed")
        xapp.rmr_free(sbuf)

        if TEST_CONTROL_ON_STARTUP and not getattr(self, "_test_sent", False):
            self._test_sent = True
            t = threading.Thread(
                target=self._send_test_control, args=(meid,), daemon=True
            )
            t.start()

    def _send_test_control(self, meid):
        """
            [TEST] Gửi 1 RIC Control Request để verify encode path end-to-end
        """
        time.sleep(TEST_CONTROL_DELAY_S)
        gnb_info = self._gnb_info.get(meid)
        rf_id = gnb_info.rc_ran_function_id if gnb_info else 3
        print(
            f"[TEST] Sending test RIC Control Request: meid={meid} "
            f"ue_id={TEST_CONTROL_UE_ID} rf_id={rf_id}"
        )
        try:
            self._rc.quarantine_ue(
                meid=meid, ue_id=TEST_CONTROL_UE_ID,
                reason="e2e_test", ran_function_id=rf_id,
            )
        except Exception as e:
            logger.error(f"[TEST] Control send failed: {e}")

    def _on_sub_failure(self, xapp, summary, sbuf):
        meid = summary.get(rmr.RMR_MS_MEID, b"").decode(errors="ignore")
        logger.error(f"[Sub] FAILURE from {meid}")
        xapp.rmr_free(sbuf)

    def _on_sub_del_resp(self, xapp, summary, sbuf):
        print("[Sub] DEL_RESP received")
        xapp.rmr_free(sbuf)

    def _on_control_ack(self, xapp, summary, sbuf):
        meid = summary.get(rmr.RMR_MS_MEID, b"").decode(errors="ignore")
        print(f"[RC] ACK from {meid}")
        xapp.rmr_free(sbuf)

    def _on_control_fail(self, xapp, summary, sbuf):
        meid = summary.get(rmr.RMR_MS_MEID, b"").decode(errors="ignore")
        logger.error(f"[RC] FAIL from {meid}")
        xapp.rmr_free(sbuf)


    def _default_handler(self, xapp, summary, sbuf):
        mtype = summary.get(rmr.RMR_MS_MSG_TYPE, 0)
        if mtype == RIC_INDICATION:
            self._on_indication(xapp, summary, sbuf)
            return
        xapp.rmr_free(sbuf)

    def _config_handler(self, xapp, config):
        print(f"[Main] Config update: {json.dumps(config)}")


    # --- Periodic Stats
    def _periodic_stats(self):
        """
            In thống kê định kỳ mỗi 30s
        """
        while True:
            time.sleep(30)
            msg = (
                f"[Stats] indications={self._indication_count} "
                f"subs={len(self._submgr.active_subs) if self._submgr else 0}"
            )
            if self._drl:
                stats = self._drl.get_stats()
                msg += (
                    f" drl_decisions={stats['total_decisions']} "
                    f"quarantined={stats['quarantine_decisions']}"
                )
            print(msg)

    # --- Manual HTTP server stdlib Python
    def _start_migrate_http(self, port=8081):
        xapp_self = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                if u.path == "/health":
                    self.send_response(200) 
                    self.end_headers()
                    self.wfile.write(b"ok\n") 
                    return
                if u.path != "/migrate":
                    self.send_response(404)
                    self.end_headers() 
                    return
                q = urllib.parse.parse_qs(u.query)
                try:
                    ue_id = int(q.get("ue_id", ["0"])[0])
                    action = q.get("action", ["quarantine"])[0]
                    if not xapp_self._gnb_info:
                        self.send_response(503) 
                        self.end_headers()
                        self.wfile.write(b"no gnb discovered\n") 
                        return
                    meid = next(iter(xapp_self._gnb_info.keys()))
                    gnb = xapp_self._gnb_info[meid]
                    rf_id = gnb.rc_ran_function_id
                    if action == "quarantine":
                        act = xapp_self._rc.set_slice_prb_quota(
                            meid=meid, slice_name="quarantine",
                            ue_id=ue_id,
                            ran_function_id=rf_id,
                        )
                        xapp_self._migrated_ues.add((meid, ue_id))
                    elif action == "release":
                        # Migrate back to slice 1 
                        act = xapp_self._rc.set_slice_prb_quota(
                            meid=meid, slice_name="priority",
                            ue_id=ue_id,
                            min_prb_pct=0, max_prb_pct=100,
                            ran_function_id=rf_id,
                        )
                        xapp_self._migrated_ues.discard((meid, ue_id))
                        try:
                            xapp_self._drl.mark_released(ue_id)
                        except Exception as e:
                            logger.warning(f"[Migrate] mark_released failed: {e}")
                        xapp_self._accum_history.pop((meid, ue_id), None)
                    else:
                        self.send_response(400); self.end_headers()
                        self.wfile.write(b"action must be quarantine|release\n")
                        return
                    self.send_response(200); self.end_headers()
                    self.wfile.write(
                        f"ok meid={meid} ue_id={ue_id} action={action} "
                        f"status={getattr(act, 'status', '?')}\n".encode()
                    )
                except Exception as e:
                    self.send_response(500); self.end_headers()
                    self.wfile.write(f"err: {e}\n".encode())

            def log_message(self, *a, **kw):
                pass

        srv = http.server.HTTPServer(("0.0.0.0", port), _Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"[Main] Migrate HTTP trigger listening on :{port}")


    # --- Shutdown
    def _shutdown(self, signum, frame):
        print(f"[Main] Signal {signum} — shutting down...")
        if self._submgr:
            self._submgr.unsubscribe_all()
        if self._drl:
            self._drl.save_model()
        self._xapp.stop()

    def run(self):
        print(f"[Main] {self._name} starting...")
        self._xapp.run()


if __name__ == "__main__":
    MyXapp().run()
