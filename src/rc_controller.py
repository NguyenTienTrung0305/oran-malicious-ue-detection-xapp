#!/usr/bin/env python3
"""
RC Controller cho network slicing enforcement.
Gửi RIC Control Request qua RMR (E2AP wrapped bằng Pycrate).

Chức năng:
  - Quản lý slice configs (normal / quarantine / priority)
  - Quarantine malicious UE (DRL quyết định)
  - Release UE về slice bình thường
  - Set PRB quota per slice
"""

import os
import time
from dataclasses import dataclass, field
from mdclogpy import Logger

from ricxappframe.xapp_frame import rmr

from asn1_codec import (
    encode_rc_control_header,
    encode_rc_control_message,
    encode_e2ap_control_request,
    RC_OID,
)

logger = Logger(name=__name__)
logger.set_level(3)

# RMR message types
RIC_CONTROL_REQ  = 12040
RIC_CONTROL_ACK  = 12041
RIC_CONTROL_FAIL = 12042

# srsRAN RC RAN Function ID
SRSRAN_RC_RAN_FUNC_ID = 3


@dataclass
class SliceConfig:
    """Cấu hình network slice."""
    sst: int = 1               # 1=eMBB, 2=URLLC, 3=mMTC
    sd: int = 0                # Slice Differentiator (24-bit), 0 = không dùng
    min_prb_ratio: int = 0     # Min PRB allocation [%]
    max_prb_ratio: int = 100   # Max PRB allocation [%]
    dedicated_prb: int = 0     # Dedicated PRBs (absolute)
    label: str = ""

    @property
    def nssai_str(self):
        if self.sd:
            return f"SST={self.sst}/SD={self.sd:#08x}"
        return f"SST={self.sst}"


@dataclass
class ControlAction:
    action_id: int
    action_type: str       # "slice_prb_quota" | "quarantine_ue" | "release_ue"
    target_meid: str
    params: dict = field(default_factory=dict)
    status: str = "pending"
    timestamp: float = field(default_factory=time.time)


class RcController:
    """
    RC Controller cho network slicing.
    Dùng Pycrate E2AP để wrap RIC Control Request.
    """

    def __init__(self, xapp_rmr=None):
        self._rmr = xapp_rmr
        self._action_counter = 0
        self._history = []

        # Slice configs mặc định
        self._slices = {
            "normal": SliceConfig(
                sst=1, sd=0,
                min_prb_ratio=20, max_prb_ratio=100,
                label="Normal Traffic",
            ),
            "quarantine": SliceConfig(
                sst=1, sd=0x000002,
                min_prb_ratio=5, max_prb_ratio=6,
                label="Quarantine (Malicious UE) - slice SD=2",
            ),
            "priority": SliceConfig(
                sst=1, sd=0x000001,
                min_prb_ratio=30, max_prb_ratio=100,
                label="Priority / Protected",
            ),
        }

        self._ue_slice_map = self._parse_ue_slice_map(
            os.environ.get("UE_SLICE_MAP", "")
        )
        if self._ue_slice_map:
            logger.info(f"[RC] UE -> slice map loaded: {self._ue_slice_map}")

        # Quarantine / restore PRB ratios when acting on a UE-specific slice
        self._quarantine_prb = (5, 6) 
        self._restore_prb    = (10, 100)

    @staticmethod
    def _parse_ue_slice_map(spec: str):
        """
        Parse UE_SLICE_MAP env string into {ue_id: (sst, sd)}
        UE_SLICE_MAP: example "42:1/0000099, 43:1/0000001, 44:1" -> UE 42 -> SST=1 SD=0000099, UE 43 -> SST=1 SD=0000001
        """
        m = {}
        if not spec:
            return m
        for item in spec.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                ue_str, slice_str = item.split(":", 1)
                ue_id = int(ue_str)
                if "/" in slice_str:
                    sst_str, sd_str = slice_str.split("/", 1)
                    sst = int(sst_str)
                else:
                    sst, sd_str = 1, slice_str
                sd = int(sd_str, 16)
                m[ue_id] = (sst, sd)
            except Exception as e:
                logger.warning(f"[RC] Bad UE_SLICE_MAP entry '{item}': {e}")
        return m

    def set_ue_slice(self, ue_id: int, sst: int, sd: int):
        self._ue_slice_map[int(ue_id)] = (int(sst), int(sd))

    def get_ue_slice(self, ue_id: int):
        return self._ue_slice_map.get(int(ue_id))

    def set_rmr(self, xapp_rmr):
        self._rmr = xapp_rmr


    def configure_slice(self, name, config):
        self._slices[name] = config
        print(f"[RC] Slice configured: {name} → {config.nssai_str}")

    def get_slice(self, name):
        return self._slices.get(name)

    def list_slices(self):
        return dict(self._slices)

    def set_slice_prb_quota(self, meid, slice_name,
                            min_prb_pct=None, max_prb_pct=None,
                            ue_id=0, ran_function_id=None):
        """Set PRB quota cho một slice trên gNB."""
        sl = self._slices.get(slice_name)
        if not sl:
            logger.error(f"[RC] Unknown slice: {slice_name}")
            return None

        prb_min = min_prb_pct if min_prb_pct is not None else sl.min_prb_ratio
        prb_max = max_prb_pct if max_prb_pct is not None else sl.max_prb_ratio
        rf_id = ran_function_id or SRSRAN_RC_RAN_FUNC_ID

        self._action_counter += 1
        action = ControlAction(
            action_id=self._action_counter,
            action_type="slice_prb_quota",
            target_meid=meid,
            params={
                "ue_id": ue_id,
                "slice_name": slice_name,
                "sst": sl.sst, "sd": sl.sd,
                "min_prb_ratio": prb_min, "max_prb_ratio": prb_max,
                "dedicated_prb": sl.dedicated_prb,
            },
        )

        self._send_control(action, rf_id)
        return action

    def quarantine_ue(self, meid, ue_id, reason="malicious",
                      ran_function_id=None):
        rf_id = ran_function_id or SRSRAN_RC_RAN_FUNC_ID
        pair = self._ue_slice_map.get(int(ue_id))
        if pair:
            sst, sd = pair
            prb_min, prb_max = self._quarantine_prb
            slice_label = f"ue{ue_id}-slice(SST={sst},SD={sd:#08x})"
        else:
            sl = self._slices["quarantine"]
            sst, sd = sl.sst, sl.sd
            prb_min, prb_max = sl.min_prb_ratio, sl.max_prb_ratio
            slice_label = "fallback-quarantine-slice"
            logger.warning(
                f"[RC] UE {ue_id} not in UE_SLICE_MAP; using fallback slice"
            )

        self._action_counter += 1
        action = ControlAction(
            action_id=self._action_counter,
            action_type="quarantine_ue",
            target_meid=meid,
            params={
                "ue_id": ue_id,
                "sst": sst, "sd": sd,
                "min_prb_ratio": prb_min,
                "max_prb_ratio": prb_max,
                "reason": reason,
                "slice": slice_label,
            },
        )

        self._send_control(action, rf_id)
        print(
            f"[RC] UE {ue_id} QUARANTINED on {meid} → {slice_label} "
            f"(PRB {prb_min}-{prb_max}%, reason: {reason})"
        )
        return action

    def release_ue(self, meid, ue_id, target_slice=None,
                   ran_function_id=None):
        rf_id = ran_function_id or SRSRAN_RC_RAN_FUNC_ID

        if target_slice is None:
            pair = self._ue_slice_map.get(int(ue_id))
            if pair:
                sst, sd = pair
                prb_min, prb_max = self._restore_prb
                slice_label = f"ue{ue_id}-slice(SST={sst},SD={sd:#08x})"
            else:
                target_slice = "normal"

        if target_slice is not None:
            sl = self._slices.get(target_slice)
            if not sl:
                logger.error(f"[RC] Unknown slice: {target_slice}")
                return None
            sst, sd = sl.sst, sl.sd
            prb_min, prb_max = sl.min_prb_ratio, sl.max_prb_ratio
            slice_label = target_slice

        self._action_counter += 1
        action = ControlAction(
            action_id=self._action_counter,
            action_type="release_ue",
            target_meid=meid,
            params={
                "ue_id": ue_id,
                "sst": sst, "sd": sd,
                "min_prb_ratio": prb_min,
                "max_prb_ratio": prb_max,
                "target_slice": slice_label,
            },
        )

        self._send_control(action, rf_id)
        print(
            f"[RC] UE {ue_id} RELEASED on {meid} → {slice_label} "
            f"(PRB {prb_min}-{prb_max}%)"
        )
        return action


    def _send_control(self, action, ran_function_id):
        """Encode và gửi RIC Control Request qua RMR."""
        if self._rmr is None:
            logger.warning(
                f"[RC] RMR not available — action {action.action_id} queued"
            )
            self._history.append(action)
            return

        try:
            p = action.params

            # 1. Encode E2SM-RC header (with ue_id!) + message
            header_bytes = encode_rc_control_header(
                ue_id=p.get("ue_id", 0),
                ric_style_type=2,
                control_action_id=6,   # Slice-level PRB quota
            )
            message_bytes = encode_rc_control_message(
                prb_min=p.get("min_prb_ratio", 0),
                prb_max=p.get("max_prb_ratio", 100),
                prb_ded=p.get("dedicated_prb", 0),
                sst=p.get("sst", 1),
                sd=p.get("sd", 0),
            )

            # 2. Wrap trong E2AP RICcontrolRequest
            payload = encode_e2ap_control_request(
                ran_function_id, header_bytes, message_bytes,
            )

            if not payload:
                action.status = "failed"
                logger.error(f"[RC] E2AP encode failed for action {action.action_id}")
                self._history.append(action)
                return

            # 3. Gửi qua RMR low-level API (BẮT BUỘC gắn MEID)
            #    E2Term đọc MEID từ RMR header để biết route SCTP
            #    xuống đúng gNB. Không có MEID -> E2Term drop ngay
            meid_bytes = action.target_meid.encode("utf-8")

            sbuf = rmr.rmr_alloc_msg(
                self._rmr._mrc,        # RMR context từ RMRXapp
                len(payload),
                payload=payload,
                gen_transaction_id=True,
                mtype=RIC_CONTROL_REQ,
                meid=meid_bytes,
            )

            sbuf = rmr.rmr_send_msg(self._rmr._mrc, sbuf)
            summary = rmr.message_summary(sbuf)
            send_state = summary.get(rmr.RMR_MS_MSG_STATE, -1)

            if send_state == 0:  # RMR_OK
                action.status = "sent"
                print(
                    f"[RC] Control sent: action={action.action_id} "
                    f"type={action.action_type} meid={action.target_meid} "
                    f"({len(payload)}B)"
                )
            else:
                action.status = "failed"
                logger.error(
                    f"[RC] RMR send failed: action {action.action_id} "
                    f"state={send_state}"
                )

            rmr.rmr_free_msg(sbuf)

        except Exception as e:
            action.status = "failed"
            logger.error(f"[RC] Control error: {e}")

        self._history.append(action)

    def get_history(self, limit=50):
        return self._history[-limit:]

