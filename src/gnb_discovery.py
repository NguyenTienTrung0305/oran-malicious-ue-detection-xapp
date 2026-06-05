#!/usr/bin/env python3
"""
gNB Discovery qua E2 Manager REST API.
Tìm gNB đã CONNECTED và lọc theo OID (KPM/RC).
"""

import os
import time
import requests
from dataclasses import dataclass, field
from mdclogpy import Logger

logger = Logger(name=__name__)
logger.set_level(3)

E2MGR_URL = os.environ.get(
    "SERVICE_RICPLT_E2MGR_HTTP",
    "http://service-ricplt-e2mgr-http.ricplt:3800",
)

KPM_OID = "1.3.6.1.4.1.53148.1.2.2.2"
RC_OID  = "1.3.6.1.4.1.53148.1.1.2.3"


@dataclass
class RanFunction:
    """Một RAN Function được gNB báo cáo"""

    # Số thứ tự cục bộ (Local ID) do chính trạm gNB này tự định nghĩa.
    # Dùng làm mã rút gọn trong E2AP để truyền tin siêu tốc độ, tiết kiệm băng thông
    # VD: Lấy KPM ứng với ran_function_id = 2
    ran_function_id: int

    # Mã định danh toàn cầu (Global ID) theo chuẩn O-RAN Alliance
    # Dùng để RIC nhận diện chính xác chức năng đó là gì
    # VD: "1.3.6.1.4.1.53148.1.2.2.2" ở mọi trạm trên thế giới đều nghĩa là KPM
    oid: str
    revision: int = 0

    @property
    def is_kpm(self):
        return "1.2.2.2" in self.oid

    @property
    def is_rc(self):
        return "1.1.2.3" in self.oid


@dataclass
class GnbInfo:
    """Thông tin gNB đã discover"""
    inventory_name: str
    connection_status: str
    ran_functions: list = field(default_factory=list)

    @property
    def has_kpm(self):
        return any(rf.is_kpm for rf in self.ran_functions)

    @property
    def has_rc(self):
        return any(rf.is_rc for rf in self.ran_functions)

    @property
    def kpm_ran_function_id(self):
        for rf in self.ran_functions:
            if rf.is_kpm:
                return rf.ran_function_id
        return None

    @property
    def rc_ran_function_id(self):
        for rf in self.ran_functions:
            if rf.is_rc:
                return rf.ran_function_id
        return None


class GnbDiscovery:
    """Discover gNBs qua E2 Manager REST API"""

    def __init__(self, e2mgr_url=None):
        self.base_url = (e2mgr_url or E2MGR_URL).rstrip("/")
        self._gnbs = {}

    def discover(self, force=False):
        """Query E2 Manager, trả về list GnbInfo đã CONNECTED"""
        url = f"{self.base_url}/v1/nodeb/states"
        print(f"[Discovery] GET {url}")

        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            nodes = resp.json()
        except Exception as e:
            logger.error(f"[Discovery] Failed to get gNBs: {e}")
            return list(self._gnbs.values())

        self._gnbs.clear()
        for node in nodes:
            inv_name = node.get("inventoryName", "")
            conn_status = node.get("connectionStatus", "UNKNOWN")
            if conn_status != "CONNECTED" or not inv_name:
                continue

            gnb = self._fetch_details(inv_name)
            if gnb:
                self._gnbs[inv_name] = gnb
                print(
                    f"[Discovery] gNB: {inv_name} "
                    f"(KPM={gnb.has_kpm}, func_id={gnb.kpm_ran_function_id}, "
                    f"RC={gnb.has_rc})"
                )

        print(f"[Discovery] Total CONNECTED: {len(self._gnbs)}")
        return list(self._gnbs.values())

    def _fetch_details(self, inv_name):
        """Fetch RAN functions cho một gNB"""
        url = f"{self.base_url}/v1/nodeb/{inv_name}"
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            info = resp.json()
        except Exception as e:
            logger.error(f"[Discovery] Details failed for {inv_name}: {e}")
            return None

        raw_funcs = info.get("gnb", {}).get("ranFunctions", [])
        ran_functions = []
        for rf in raw_funcs:
            rf_id = rf.get("ranFunctionId") or rf.get("ranFunctionID", 0)
            oid = rf.get("ranFunctionOid") or rf.get("ranFunctionOID", "")
            rev = rf.get("ranFunctionRevision", 0)
            ran_functions.append(
                RanFunction(ran_function_id=rf_id, oid=oid, revision=rev)
            )

        return GnbInfo(
            inventory_name=inv_name,
            connection_status="CONNECTED",
            ran_functions=ran_functions,
        )

    def get_kpm_gnbs(self):
        """Chỉ trả về gNBs hỗ trợ KPM"""
        if not self._gnbs:
            self.discover()
        return [g for g in self._gnbs.values() if g.has_kpm]

    def wait_for_gnb(self, timeout_s=120, poll_interval=5):
        """
            Block cho đến khi có ít nhất 1 gNB hỗ trợ KPM connected với RIC
        """
        print(f"[Discovery] Waiting for KPM gNB (timeout={timeout_s}s)...")
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            gnbs = self.discover(force=True)
            kpm_gnbs = [g for g in gnbs if g.has_kpm]
            if kpm_gnbs:
                gnb = kpm_gnbs[0]
                print(f"[Discovery] KPM gNB found: {gnb.inventory_name}")
                return gnb
            time.sleep(poll_interval)
        logger.error("[Discovery] Timeout waiting for KPM gNB!")
        return None


# --- Backward-compatible helper

def discover_kpm_capable_gnbs():
    discovery = GnbDiscovery()
    gnbs = discovery.get_kpm_gnbs()
    return [
        {
            "meid": g.inventory_name,
            "ran_function_id": g.kpm_ran_function_id,
            "oid": KPM_OID,
        }
        for g in gnbs
    ]
