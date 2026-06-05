#!/usr/bin/env python3
"""
Subscription Manager REST client (camelCase JSON, webhook callback).

Flow:
  1. Start Flask webhook server (port 8088) để nhận SubMgr callbacks
  2. POST /ric/v1/subscriptions tới SubMgr (camelCase JSON)
  3. SubMgr gọi webhook khi subscription thành công/thất bại
  4. Lưu subid vào SDL cho crash recovery
  5. DELETE khi shutdown
"""

import json
import threading
import time
import requests
from flask import Flask, request, jsonify
from mdclogpy import Logger

logger = Logger(name=__name__)
logger.set_level(3)

# SubMgr endpoints
SUBMGR_BASE_URL = "http://service-ricplt-submgr-http.ricplt:8088"
SUBSCRIBE_URL   = f"{SUBMGR_BASE_URL}/ric/v1/subscriptions"
UNSUBSCRIBE_URL = SUBMGR_BASE_URL + "/ric/v1/subscriptions/{subid}"

# xApp webhook config
XAPP_HTTP_PORT = 8088
XAPP_RMR_PORT  = 4560

# Hardcode notification path trong O-RAN (SubMgr sẽ gọi tới đây)
NOTIF_PATH     = "/ric/v1/subscriptions/response" 


class SubscriptionManager:
    """
    Quản lý subscriptions với SubMgr qua HTTP REST.
    Dùng camelCase JSON đúng chuẩn O-RAN SC.
    """

    def __init__(self, xapp_name="my-xapp",
                 xapp_ip="service-ricxapp-my-xapp-http.ricxapp",
                 sdl_client=None):
        self.xapp_name = xapp_name
        self.xapp_ip = xapp_ip
        self.sdl_client = sdl_client
        self.active_subs = {}    # subid -> {meid, metric_names, ...}
        self._event_counter = 0
        self._pending = {}       # str(xapp_event_id) -> info dict
        
        # Block thread, cụ thể có 2 thread A và B cùng chạy đến đoạn có mã code with self._lock:
        # Nhưng thằng A đến trước, lúc này chỉ có thằng A được đi vào đoạn code trong with, thằng B đứng im ngoài đấy chờ
        # Khi thằng A xong việc đoạn code trong with, nó sẽ tự động giải phóng lock, lúc này thằng B mới được phép vào đoạn code trong with
        # Áp dụng với mọi đoạn code có with self._lock, đảm bảo chỉ có 1 thread được phép truy cập vào các đoạn code này tại cùng thời điểm
        self._lock = threading.Lock()

        # Start webhook server, server thì passive listen, tức là Nó chỉ mở socket TCP :8088 rồi ngủ chờ kết nối tới.
        # Khi có kết nối tới, nó mở dậy xử lý.
        # Cụ thể khi SubMgr xử lý xong, nó tự gọi đến path NOTIF_PATH ở port 8088 của xApp (standard O-RAN callback), 
        # Flask sẽ nhận được request này và gọi hàm callback tương ứng (ở đây là _subscription_notif) để xử lý request.
        self._app = Flask(__name__)
        self._app.add_url_rule(
            NOTIF_PATH, 
            "subscription_notif",
            self._subscription_notif, 
            methods=["POST"],
        )

        self._webhook_thread = threading.Thread(
            target=self._run_webhook, 
            daemon=True
        )
        self._webhook_thread.start()
        print(f"[SubMgr] Webhook started on port {XAPP_HTTP_PORT}")

    def _run_webhook(self):
        import logging as _log
        _log.getLogger("werkzeug").setLevel(_log.ERROR)
        self._app.run(
            host="0.0.0.0", 
            port=XAPP_HTTP_PORT,
            threaded=True, 
            use_reloader=False, 
            debug=False,
        )

    # --- Webhook callback handler
    def _subscription_notif(self):
        """
        SubMgr gọi endpoint này khi subscription được xử lý
        """
        data = request.get_json(force=True, silent=True) or {}
        print(f"[SubMgr] Notification: {json.dumps(data, indent=2)}")

        sub_id = data.get("SubscriptionId", "")
        instances = data.get("SubscriptionInstances", [{}])
        status = instances[0] if instances else {}

        xapp_event_id = str(
            status.get("XappEventInstanceId")
            or status.get("XappEventInstanceID")
            or ""
        )
        e2_event_id = status.get("E2EventInstanceId", -1)
        error_cause = status.get("ErrorCause", "").strip()
        error_source = status.get("ErrorSource", "").strip()

        # Lấy pending info
        with self._lock:
            pending_info = self._pending.pop(xapp_event_id, None)

        # Xử lý lỗi
        if error_cause:
            print(f"[SubMgr] FAILED: cause={error_cause}, source={error_source}")
            if pending_info:
                retries = pending_info.get("retry_count", 0)
                if retries < 3:
                    print(
                        f"[SubMgr] Retry {pending_info['meid']} in 5s "
                        f"(attempt {retries + 1}/3)..."
                    )
                    threading.Timer(
                        5.0, self._retry_subscribe, args=[pending_info]
                    ).start()
                else:
                    logger.error(
                        f"[SubMgr] Max retries for {pending_info['meid']}"
                    )
            return jsonify({"status": "error"}), 200

        if not sub_id:
            logger.error("[SubMgr] No SubscriptionId in notification!")
            return jsonify({"status": "error"}), 200

        # Subscription thành công
        with self._lock:
            meid = pending_info["meid"] if pending_info else "unknown"
            metric_names = (
                pending_info.get("metric_names", []) if pending_info else []
            )
            self.active_subs[sub_id] = {
                "meid": meid,
                "e2_event_id": e2_event_id,
                "metric_names": metric_names,
            }

        self._persist_subid(sub_id, meid)
        print(f"[SubMgr] OK: subid={sub_id}, meid={meid}")
        return jsonify({"status": "ok"}), 200

    def _retry_subscribe(self, info):
        """
        Retry subscription bị lỗi
        """
        print(f"[SubMgr] Retrying {info['meid']}...")
        new_event_id = self.subscribe(
            meid=info["meid"],
            ran_function_id=info["ran_function_id"],
            event_trigger_bytes=info["event_trigger_bytes"],
            action_def_bytes=info["action_def_bytes"],
            metric_names=info.get("metric_names", []),
        )
        with self._lock:
            key = str(new_event_id)
            if key in self._pending:
                self._pending[key]["retry_count"] = (
                    info.get("retry_count", 0) + 1
                )

    # --- Subscribe
    def subscribe(self, meid, ran_function_id,
                  event_trigger_bytes, action_def_bytes,
                  metric_names=None):
        """
        Gửi KPM subscription request tới SubMgr.
        Trả về xapp_event_instance_id (str) để tracking.
        """
        with self._lock:
            self._event_counter += 1
            xapp_event_id = self._event_counter
            self._pending[str(xapp_event_id)] = {
                "meid": meid,
                "ran_function_id": ran_function_id,
                "event_trigger_bytes": event_trigger_bytes,
                "action_def_bytes": action_def_bytes,
                "metric_names": metric_names or [],
                "retry_count": 0,
            }

        # camelCase JSON payload (SubMgr requirement)
        payload = {
            "subscriptionId": "",
            "clientEndpoint": {
                "host": self.xapp_ip,
                "httpPort": XAPP_HTTP_PORT,
                "rmrPort": XAPP_RMR_PORT,
            },
            "meid": meid,
            "ranFunctionID": ran_function_id,
            "e2SubscriptionDirectives": {
                "e2TimeoutTimerValue": 5,
                "e2RetryCount": 4,
                "rmrRoutingNeeded": True,
            },
            "subscriptionDetails": [
                {
                    "xappEventInstanceId": xapp_event_id,
                    "eventTriggers": list(event_trigger_bytes),
                    "actionToBeSetupList": [
                        {
                            "actionID": 1,
                            "actionType": "report",
                            "actionDefinition": list(action_def_bytes),
                        }
                    ],
                }
            ],
        }

        print(f"[SubMgr] POST subscription for {meid} (func={ran_function_id})")

        try:
            # xApp gửi POST tới SubMgr để tạo subscription
            # Submgr ở đây chỉ xử lý sơ bộ (parse JSON, validate format, lưu vào pending list)
            # Submgr trả về status code - 200 / 201	-> "Tao nhận request rồi, format hợp lệ, sẽ xử lý" (chưa biết kết quả)
            resp = requests.post(
                SUBSCRIBE_URL, json=payload,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            if resp.status_code in (200, 201):
                print(f"[SubMgr] POST accepted: {resp.status_code}")
            else:
                logger.error(
                    f"[SubMgr] POST failed: {resp.status_code} {resp.text}"
                )
        except requests.exceptions.RequestException as e:
            logger.error(f"[SubMgr] POST exception: {e}")

        return str(xapp_event_id)

    # --- Unsubscribe
    def unsubscribe(self, sub_id):
        """Delete một subscription"""
        url = UNSUBSCRIBE_URL.format(subid=sub_id)
        try:
            resp = requests.delete(url, timeout=10)
            if resp.status_code in (200, 204):
                print(f"[SubMgr] Unsubscribed: {sub_id}")
                with self._lock:
                    self.active_subs.pop(sub_id, None)
                self._remove_subid(sub_id)
            else:
                logger.error(
                    f"[SubMgr] Unsubscribe failed: {sub_id} ({resp.status_code})"
                )
        except requests.exceptions.RequestException as e:
            logger.error(f"[SubMgr] Unsubscribe exception: {e}")

    def unsubscribe_all(self):
        """Unsubscribe tất cả trước khi shutdown"""
        print(f"[SubMgr] Cleaning up {len(self.active_subs)} subscriptions")
        for sub_id in list(self.active_subs.keys()):
            self.unsubscribe(sub_id)

    # --- Helpers
    def get_metric_names(self, sub_id=None):
        """
            Lấy metric names cho subscription
        """
        if sub_id and sub_id in self.active_subs:
            return self.active_subs[sub_id].get("metric_names", [])
        
        # Trả về metric_names của sub đầu tiên
        for info in self.active_subs.values():
            names = info.get("metric_names", [])
            if names:
                return names
        return []

    def restore_from_sdl(self):
        """Khôi phục subscriptions từ SubMgr sau crash"""
        try:
            resp = requests.get(SUBSCRIBE_URL, timeout=10)
            if resp.status_code == 200:
                subs = resp.json()
                for sub in subs:
                    sub_id = sub.get("SubscriptionId", "")
                    meid = sub.get("Meid", "")
                    if sub_id:
                        self.active_subs[sub_id] = {"meid": meid}
                        print(f"[SubMgr] Restored: subid={sub_id}, meid={meid}")
        except Exception as e:
            logger.warning(f"[SubMgr] Could not restore: {e}")

    def _persist_subid(self, sub_id, meid):
        if self.sdl_client:
            try:
                self.sdl_client.set(
                    "my-xapp",
                    {f"sub:{sub_id}": json.dumps({"meid": meid})}
                )
            except Exception as e:
                logger.warning(f"[SDL] Persist failed: {e}")

    def _remove_subid(self, sub_id):
        if self.sdl_client:
            try:
                self.sdl_client.remove("my-xapp", {f"sub:{sub_id}"})
            except Exception as e:
                logger.warning(f"[SDL] Remove failed: {e}")
