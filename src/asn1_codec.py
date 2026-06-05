#!/usr/bin/env python3
"""
ASN.1 Codec cho E2AP + E2SM-KPM + E2SM-RC.
  - Dùng e2sm_kpm_codec (compiled) cho KPM
  - Dùng asn1tools cho RC
  - Dùng pycrate_asn1dir.E2AP cho outer E2AP layer
"""

import os
import random
from mdclogpy import Logger
from pycrate_asn1dir import E2AP
import e2sm_kpm_codec

# srsRAN yêu cầu cấu trúc nested Structure-in-Structure có sibling Element 
# Dùng asn1tools cho E2SM-RC (pycrate 0.7.11 có bug với nested Structure-in-Structure có sibling Element)
# Header + Message RC encode bằng asn1tools, E2AP outer vẫn giữ pycrate
import asn1tools

_ASN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RC_ASN_FILES = [
    os.path.join(_ASN_DIR, 'e2sm-v5.00.asn'),
    os.path.join(_ASN_DIR, 'e2sm-rc-v5.00.asn'),
]
try:
    _rc_asn = asn1tools.compile_files(_RC_ASN_FILES, 'per')
except Exception as _e:
    _rc_asn = None
    Logger(name=__name__).error(f"[ASN1] asn1tools compile E2SM-RC failed: {_e}")

logger = Logger(name=__name__)
logger.set_level(3)



"""
--- srsRAN KPM Metrics (15 metrics thực tế từ RAN Function Definition)

PRB:+ Đơn vị nhỏ nhất nhà mạng cấp cho UE. Hãy tưởng tượng PRB là những ngăn tủ trong một cái kho lớn. 
        Khi bạn muốn gửi hàng, nhà mạng sẽ cấp cho bạn một số lượng ngăn tủ nhất định.
    + PRB có hạn. Số lượng PRB phụ thuộc vào bandwidth 
    + Lượng dữ liệu mỗi PRB chở được không cố định mà phục thuộc vào chất lượng sóng  
    
throughput: Tốc độ truyền tải dữ liệu. Được tính bằng tổng lượng dữ liệu mỗi prb chở được chia cho đơn vị thời gian
"""
KPM_OID = "1.3.6.1.4.1.53148.1.2.2.2"
RC_OID  = "1.3.6.1.4.1.53148.1.1.2.3"

SRSRAN_KPM_METRICS = [
    "DRB.AirIfDelayUl",
    "DRB.RlcDelayUl",
    "DRB.RlcPacketDropRateDl",
    "DRB.RlcSduDelayDl",
    "DRB.RlcSduTransmittedVolumeDL",
    "DRB.RlcSduTransmittedVolumeUL",
    "DRB.UEThpDl",
    "DRB.UEThpUl",
    "RACH.PreambleDedCell",
    "RRU.PrbAvailDl",
    "RRU.PrbAvailUl",
    "RRU.PrbTotDl",
    "RRU.PrbTotUl",
    "RRU.PrbUsedDl",
    "RRU.PrbUsedUl",
]

DRL_METRICS = [
    "DRB.UEThpDl",                  # throughput DL
    "DRB.UEThpUl",                  # throughput UL
    "RRU.PrbUsedDl",                # PRB DL use
    "RRU.PrbUsedUl",                # PRB UL use
    "RRU.PrbAvailDl",               # PRB DL available
    "DRB.AirIfDelayUl",             # link delay
    "DRB.RlcSduDelayDl",            # queue delay DL
    "DRB.RlcPacketDropRateDl",      # loss/error
]

# Metric groups cho subscription
METRIC_GROUPS = {
    "all": SRSRAN_KPM_METRICS,
    "drl_malicious_ue": DRL_METRICS,
    "throughput": ["DRB.UEThpDl", "DRB.UEThpUl"],
    "prb": [
        "RRU.PrbAvailDl", "RRU.PrbAvailUl",
        "RRU.PrbTotDl", "RRU.PrbTotUl",
        "RRU.PrbUsedDl", "RRU.PrbUsedUl",
    ],
    "latency": ["DRB.AirIfDelayUl", "DRB.RlcDelayUl", "DRB.RlcSduDelayDl"],
}

# E2SM-KPM ReportingPeriod enum mapping (ms -> ASN.1 enum index)
REPORT_PERIOD_MAP = {
    10: 0, 20: 1, 32: 2, 50: 3, 64: 4, 70: 5, 80: 6,
    128: 7, 160: 8, 256: 9, 320: 10, 512: 11, 640: 12,
    1024: 13, 1280: 14, 2048: 15, 2560: 16, 5120: 17, 10240: 18,
}


def get_metrics_for_group(group_name):
    if group_name not in METRIC_GROUPS:
        raise ValueError(
            f"Unknown metric group: {group_name}. "
            f"Valid: {list(METRIC_GROUPS.keys())}"
        )
    return list(METRIC_GROUPS[group_name])


# --- E2SM-KPM Encoders

def encode_kpm_event_trigger(period_ms=1000):
    """
    Encode E2SM-KPM EventTriggerDefinition Format1 (APER).
    Tự map sang enum index gần nhất nếu period_ms không nằm trong bảng.
    """
    valid = sorted(REPORT_PERIOD_MAP.keys())
    closest = min(valid, key=lambda x: abs(x - period_ms))
    if closest != period_ms:
        logger.warning(f"[ASN1] Period {period_ms}ms không hợp lệ, dùng {closest}ms")

    try:
        trigger = e2sm_kpm_codec.E2SM_KPM_IEs.E2SM_KPM_EventTriggerDefinition
        trigger.set_val({
            'eventDefinition-formats': ('eventDefinition-Format1', {
                'reportingPeriod': REPORT_PERIOD_MAP[closest]
            })
        })
        result = trigger.to_aper()
        logger.info(f"[ASN1] EventTrigger encoded ({len(result)}B, period={closest}ms)")
        return result
    except Exception as e:
        logger.error(f"[ASN1] Lỗi encode EventTrigger: {e}")
        return b''


def encode_kpm_action_definition(metric_names, granularity_ms=1000, style=1,
                                  ue_ids=None):
    """
    Encode E2SM-KPM ActionDefinition (APER).

    style=1: (cell-level aggregate) — không phân biệt UE
    style=3: (per-UE conditional, srsRAN chỉ trả per-UE cho metric đầu)
    style=5: (multiple UEs, per-UE on ALL metrics)
    """
    try:
        meas_info_list = []
        for name in metric_names:
            meas_info_list.append({
                'measType': ('measName', name),
                'labelInfoList': [{'measLabel': {'noLabel': 'true'}}]
            })

        action_def = e2sm_kpm_codec.E2SM_KPM_IEs.E2SM_KPM_ActionDefinition

        if style == 5:
            if not ue_ids or len(ue_ids) < 2:
                raise ValueError("Style 5 requires ue_ids list with >= 2 UEs")
            matching_ue_list = [
                {'ueID': ('gNB-DU-UEID', {'gNB-CU-UE-F1AP-ID': int(uid)})} for uid in ue_ids
            ]
            action_def.set_val({
                'ric-Style-Type': 5,
                'actionDefinition-formats': ('actionDefinition-Format5', {
                    'matchingUEidList': matching_ue_list,
                    'subscriptionInfo': {
                        'measInfoList': meas_info_list,
                        'granulPeriod': granularity_ms,
                    },
                })
            })
        elif style == 3:
            action_def.set_val({
                'ric-Style-Type': 3,
                'actionDefinition-formats': ('actionDefinition-Format3', {
                    'measCondList': [
                        {
                            'measType': ('measName', name),
                            'matchingCond': [{
                                'matchingCondChoice': (
                                    'measLabel',
                                    {'noLabel': 'true'}
                                ),
                            }],
                        }
                        for name in metric_names
                    ],
                    'granulPeriod': granularity_ms,
                })
            })
        else:
            # Format1: cell-level aggregate
            action_def.set_val({
                'ric-Style-Type': 1,
                'actionDefinition-formats': ('actionDefinition-Format1', {
                    'measInfoList': meas_info_list,
                    'granulPeriod': granularity_ms,
                })
            })

        result = action_def.to_aper()
        logger.info(
            f"[ASN1] ActionDef Style{style} encoded ({len(result)}B, "
            f"{len(metric_names)} metrics)"
        )
        return result
    except Exception as e:
        logger.error(f"[ASN1] Lỗi encode ActionDefinition Style{style}: {e}")
        return b''


# --- E2AP Outer Layer Decoder

def decode_e2ap_indication(raw_bytes):
    """
    Decode outer E2AP RIC Indication PDU (Pycrate built-in E2AP).
    Trả về dict chứa indication_header, indication_message (bytes) + metadata.
    
    Input decode:
    """
    result = {}
    try:
        pdu = E2AP.E2AP_PDU_Descriptions.E2AP_PDU
        pdu.from_aper(raw_bytes)
        val = pdu.get_val()

        if not val or val[0] != 'initiatingMessage':
            return {}

        init_msg = val[1]
        if init_msg.get('procedureCode', -1) != 5:  # 5 = RIC Indication
            return {}

        ric_ind = init_msg.get('value', {})
        if hasattr(ric_ind, 'get_val'):
            ric_ind = ric_ind.get_val()

        # Pycrate returns tuple ('RICindication', {dict}) — unwrap it
        if isinstance(ric_ind, tuple) and len(ric_ind) == 2:
            ric_ind = ric_ind[1]

        ies = (
            ric_ind.get('protocolIEs', [])
            if isinstance(ric_ind, dict)
            else []
        )

        for ie in ies:
            if not isinstance(ie, dict):
                continue
            ie_id = ie.get('id', 0)
            ie_val = ie.get('value', ('', {}))
            if isinstance(ie_val, tuple) and len(ie_val) == 2:
                ie_val = ie_val[1]

            if ie_id == 25:     # RICindicationHeader
                result['indication_header'] = (
                    ie_val if isinstance(ie_val, bytes) else bytes(ie_val)
                )
            elif ie_id == 26:   # RICindicationMessage
                result['indication_message'] = (
                    ie_val if isinstance(ie_val, bytes) else bytes(ie_val)
                )
            elif ie_id == 5:    # RANfunctionID
                result['ran_function_id'] = ie_val
            elif ie_id == 29:   # RICrequestID 
                if isinstance(ie_val, dict):
                    result['request_id'] = ie_val.get('ricRequestorID', 0)
                    result['instance_id'] = ie_val.get('ricInstanceID', 0)

    except Exception as e:
        logger.error(f"[ASN1] E2AP decode failed: {e}")

    return result


# --- E2SM-KPM Indication Decoder

def _convert_kpm_value(record):
    """Convert Pycrate KPM measurement value to Python number."""
    if not isinstance(record, tuple) or len(record) != 2:
        return record
    vtype, vval = record
    if vtype == 'integer':
        return vval
    elif vtype == 'real':
        # Pycrate REAL: (mantissa, base, exponent)
        if isinstance(vval, tuple) and len(vval) == 3:
            mantissa, base, exp = vval
            return mantissa * (base ** exp)
        return float(vval)
    elif vtype == 'noValue':
        return 0
    return vval


def _extract_ue_id(ue_id_choice):
    """Extract UE identifier từ E2SM-KPM UEID CHOICE"""
    if not isinstance(ue_id_choice, tuple) or len(ue_id_choice) != 2:
        return str(ue_id_choice)
    ue_type, ue_val = ue_id_choice
    if not isinstance(ue_val, dict):
        return str(ue_val)
    if 'amf-UE-NGAP-ID' in ue_val:
        return str(ue_val['amf-UE-NGAP-ID'])
    if 'gNB-CU-UE-F1AP-ID' in ue_val:
        return str(ue_val['gNB-CU-UE-F1AP-ID'])
    if 'ran-UEID' in ue_val:
        raw = ue_val['ran-UEID']
        return raw.hex() if isinstance(raw, bytes) else str(raw)
    return f"{ue_type}:{id(ue_val)}"


def _decode_meas_report(meas_data, meas_info_list, fallback_names):
    """Decode measData + measInfoList -> dict {metric_name: value}"""
    # Extract metric names from measInfoList
    names = []
    for info in meas_info_list:
        mtype = info.get('measType', ('', ''))
        if isinstance(mtype, tuple) and len(mtype) == 2:
            names.append(mtype[1])
        else:
            names.append(str(mtype))
    if not names:
        names = fallback_names

    measurements = {name: 0 for name in names}
    if meas_data:
        records = meas_data[0].get('measRecord', [])
        for idx, record in enumerate(records):
            if idx < len(names):
                measurements[names[idx]] = _convert_kpm_value(record)

    return measurements


def decode_kpm_indication(indication_header_bytes, indication_message_bytes,
                          metric_names=None):
    """
    Decode E2SM-KPM IndicationMessage: chỉ xử lý Format1, Format2 (conditional), Format3 (per-UE).
    Cấu trúc Format3 cho style4 và style5:
        + Giống nhau ở vỏ ngoài
        + Khác ở measInfoList bên trong measReport: style4 chỉ có 1 metric, style5 có nhiều metric (được xác định trong measInfoList). 

    Supports:
      Action Definition (encode)                            ->      Indication Message (decode)
        Style1 (cell-level)                                             Format1 (Với Style1, Indication trả về formar1)
        Style2 (per-UE conditional)                                     Format2
        Style3 (multi-UE, multi-metrics, 1 value/metrics)               Format2 (Với style3, metrics là metrics tổng hợp cho tất cả UE, không phân biệt UE nào)
        Style4 (multi-UE, single metric)                                Format3
        Style5 (multi-UE, multi-metric, n values/metrics)               Format3 (Với style5, metrics được phân biệt rõ ràng trong measInfoList, mỗi UE có giá trị riêng cho từng metric)

    """
    if metric_names is None:
        metric_names = SRSRAN_KPM_METRICS

    result = {"header": {}, "measurements": {}, "ue_list": []}

    try:
        if not indication_message_bytes:
            return result

        msg = e2sm_kpm_codec.E2SM_KPM_IEs.E2SM_KPM_IndicationMessage
        msg.from_aper(indication_message_bytes)
        val = msg.get_val()

        fmt_wrapper = val.get('indicationMessage-formats') if isinstance(val, dict) else None
        if not fmt_wrapper or not isinstance(fmt_wrapper, tuple):
            return result

        fmt_name, fmt_body = fmt_wrapper
        import sys
        if isinstance(fmt_body, dict):
            _mdata = fmt_body.get('measData', [])           # format1, format2
            _minfo = fmt_body.get('measInfoList', [])       # format1
            _mcond = fmt_body.get('measCondUEidList', [])   # format2
            _ue_rep = fmt_body.get('ueMeasReportList', [])  # format3
            
            print(f"[KPM-RAW] fmt={fmt_name} "
                  f"measData({len(_mdata)})={_mdata} "
                  f"measInfoList({len(_minfo)})={_minfo} "
                  f"measCondUEidList({len(_mcond)})={_mcond} "
                  f"ueMeasReportList({len(_ue_rep)})={_ue_rep}",
                  flush=True, file=sys.stdout)
        else:
            print(f"[KPM-RAW] fmt={fmt_name} body={fmt_body}", flush=True, file=sys.stdout)

        if fmt_name == 'indicationMessage-Format1':
            meas_data = fmt_body.get('measData', [])
            meas_info = fmt_body.get('measInfoList', [])
            measurements = _decode_meas_report(meas_data, meas_info, metric_names)
            result["measurements"] = measurements
            result["ue_list"] = [("cell", measurements)]

        elif fmt_name == 'indicationMessage-Format2':
            meas_data = fmt_body.get('measData', [])
            cond_list = fmt_body.get('measCondUEidList', [])

            # list ueID
            involved_ues = []
            if cond_list:
                first_cond = cond_list[0]
                for u in first_cond.get('matchingUEidList', []):
                    uid = _extract_ue_id(u.get('ueID', ''))
                    if uid is not None and uid not in involved_ues:
                        involved_ues.append(uid)
                        
            # get metrics names follow the order in measCondUEidList 
            metric_names_in_order = []
            for cond in cond_list:
                mtype = cond.get('measType', ('', ''))
                name = mtype[1] if isinstance(mtype, tuple) and len(mtype) == 2 else str(mtype)
                metric_names_in_order.append(name)
                
            
            # Decode aggregate values từ measData[0].measRecord
            aggregate_metrics = {}
            if meas_data:
                records = meas_data[0].get('measRecord', [])
                for i, record in enumerate(records):
                    if i < len(metric_names_in_order):
                        aggregate_metrics[metric_names_in_order[i]] = _convert_kpm_value(record)
            
            # Pad missing metrics với 0
            all_metric_names = metric_names if metric_names else metric_names_in_order
            for name in all_metric_names:
                aggregate_metrics.setdefault(name, 0)
                
            
            if involved_ues:
                for uid in involved_ues:
                    result["ue_list"].append((uid, dict(aggregate_metrics)))
            else:
                result["ue_list"].append(("cell", dict(aggregate_metrics)))
            
            if result["ue_list"]:
                result["measurements"] = result["ue_list"][0][1]
            

        elif fmt_name == 'indicationMessage-Format3':
            # Per-UE report: explicit ueID per entry
            ue_report_list = fmt_body.get('ueMeasReportList', [])

            for report in ue_report_list:
                uid = _extract_ue_id(report.get('ueID', ''))
                meas_report = report.get('measReport', {})
                meas_data = meas_report.get('measData', [])
                meas_info = meas_report.get('measInfoList', [])
                measurements = _decode_meas_report(
                    meas_data, meas_info, metric_names
                )
                result["ue_list"].append((uid, measurements))

            if result["ue_list"]:
                result["measurements"] = result["ue_list"][0][1]

    except Exception as e:
        logger.error(f"[ASN1] KPM decode failed: {e}")

    return result


# --- E2SM-RC Encoders 
#
# srsRAN RC RAN Parameter IDs (from RAN Function Definition):
#   1 = RRM Policy Ratio List (LIST)
#   2 = RRM Policy Ratio Group (STRUCTURE)
#   3 = RRM Policy (STRUCTURE)
#   4 = PLMN Identity
#   5 = S-NSSAI (STRUCTURE)
#   6 = SST
#   7 = SD
#   8 = Min PRB Policy Ratio
#   9 = Max PRB Policy Ratio
#  10 = Dedicated PRB Policy Ratio
#
# RC Control Style 2 = Radio Resource Allocation Control
# Control Action ID 6 = Slice-level PRB quota

# Default PLMN: MCC=001, MNC=01 -> BCD encoded: 00 F1 10
DEFAULT_PLMN = bytes([0x00, 0xF1, 0x10])


def _build_ue_id_for_header(ue_id):
    """
    Build UEID CHOICE value cho ControlHeader Format1 style2 / action6
    srsRAN yêu cầu gNB-DU-UEID với gNB-CU-UE-F1AP-ID

    ue_id: int (gNB-CU-UE-F1AP-ID) — dict/"cell" -> 0
    """
    if isinstance(ue_id, dict):
        f1ap_id = ue_id.get('gnb_cu_ue_f1ap_id',
                            ue_id.get('amf_ue_ngap_id', 0))
    else:
        try:
            f1ap_id = int(ue_id) if ue_id != "cell" else 0
        except (ValueError, TypeError):
            f1ap_id = 0

    return ('gNB-DU-UEID', {'gNB-CU-UE-F1AP-ID': f1ap_id})


def encode_rc_control_header(ue_id=0, ric_style_type=2, control_action_id=6):
    """
    Encode E2SM-RC ControlHeader Format1 (APER) — khớp với srsRAN.
    ueID = gNB-DU-UEID/gNB-CU-UE-F1AP-ID cho style 2/action 6.
    """
    if _rc_asn is None:
        logger.error("[ASN1] RC asn1tools module not loaded")
        return b''
    try:
        ue_id_val = _build_ue_id_for_header(ue_id)
        result = _rc_asn.encode('E2SM-RC-ControlHeader', {
            'ric-controlHeader-formats': ('controlHeader-Format1', {
                'ueID': ue_id_val,
                'ric-Style-Type': ric_style_type,
                'ric-ControlAction-ID': control_action_id,
            })
        })
        logger.info(
            f"[ASN1] RC ControlHeader encoded ({len(result)}B, "
            f"ue_id={ue_id}, style={ric_style_type}, action={control_action_id})"
        )
        return result
    except Exception as e:
        logger.error(f"[ASN1] RC ControlHeader encode failed: {e}")
        return b''


def encode_rc_control_message(prb_min=0, prb_max=100, prb_ded=0,
                               sst=1, sd=1, plmn=None):
    """
    Encode E2SM-RC ControlMessage Format1 (APER) — Style 2 / Action 6
    (Slice-level PRB quota). Dùng asn1tools để encode cấu trúc nested đúng
    Cấu trúc (khớp srsRAN):

      ID=1 RRM Policy Ratio List (LIST)
        |- ID=2 RRM Policy Ratio Group (STRUCTURE)
            |- ID=3 RRM Policy (STRUCTURE)
            │   |- ID=5 RRM Policy Member List (LIST)
            │       |- ID=6 RRM Policy Member (STRUCTURE)
            │           |- ID=7 PLMN Identity (ELEMENT, valueOctS)
            │           |- ID=8 S-NSSAI (STRUCTURE)
            │               |- ID=9  SST (ELEMENT, valueOctS 1B)
            │               |- ID=10 SD  (ELEMENT, valueOctS 3B)
            |- ID=11 Min PRB Policy Ratio (ELEMENT, valueInt)
            |- ID=12 Max PRB Policy Ratio (ELEMENT, valueInt)
            |- ID=13 Dedicated PRB Policy Ratio (ELEMENT, valueInt)

    Dùng ranP-Choice-ElementFalse (không ranP-Choice-ElementTrue)
    """
    if _rc_asn is None:
        logger.error("[ASN1] RC asn1tools module not loaded")
        return b''

    if plmn is None:
        plmn = DEFAULT_PLMN

    prb_min = max(0, min(int(prb_min), 100))
    prb_max = max(0, min(int(prb_max), 100))
    prb_ded = max(0, min(int(prb_ded), 100))
    if prb_max < prb_min:
        logger.error(f"[ASN1] RC: max_prb ({prb_max}) < min_prb ({prb_min})")
        return b''

    sst_bytes = int(sst).to_bytes(1, byteorder='big')
    sd_bytes  = int(sd if sd else 1).to_bytes(3, byteorder='big')

    def _elem(ran_id, val_tuple):
        return {'ranParameter-ID': ran_id,
                'ranParameter-valueType': ('ranP-Choice-ElementFalse',
                    {'ranParameter-value': val_tuple})}

    def _struct(ran_id, sub_params):
        return {'ranParameter-ID': ran_id,
                'ranParameter-valueType': ('ranP-Choice-Structure',
                    {'ranParameter-Structure':
                        {'sequence-of-ranParameters': sub_params}})}

    def _list(ran_id, sub_items):
        return {'ranParameter-ID': ran_id,
                'ranParameter-valueType': ('ranP-Choice-List',
                    {'ranParameter-List':
                        {'list-of-ranParameter':
                            [{'sequence-of-ranParameters': item}
                             for item in sub_items]}})}

    try:
        snssai = _struct(8, [
            _elem(9,  ('valueOctS', sst_bytes)),
            _elem(10, ('valueOctS', sd_bytes)),
        ])
        policy_member = _struct(6, [
            _elem(7, ('valueOctS', plmn)),
            snssai,
        ])
        member_list   = _list(5, [[policy_member]])
        rrm_policy    = _struct(3, [member_list])
        policy_group  = _struct(2, [
            rrm_policy,
            _elem(11, ('valueInt', prb_min)),
            _elem(12, ('valueInt', prb_max)),
            _elem(13, ('valueInt', prb_ded)),
        ])
        policy_ratio_list = _list(1, [[policy_group]])

        msg_dict = {
            'ric-controlMessage-formats': ('controlMessage-Format1', {
                'ranP-List': [policy_ratio_list],
            })
        }
        result = _rc_asn.encode('E2SM-RC-ControlMessage', msg_dict)
        logger.info(
            f"[ASN1] RC ControlMessage encoded ({len(result)}B, "
            f"SST={sst}, SD={sd:#06x}, PRB={prb_min}-{prb_max}%, ded={prb_ded})"
        )
        return result
    except Exception as e:
        logger.error(f"[ASN1] RC ControlMessage encode failed: {e}")
        return b''


def encode_e2ap_control_request(ran_function_id, header_bytes, message_bytes):
    """Wrap RC header+message trong E2AP RICcontrolRequest PDU -> APER bytes."""
    try:
        pdu = E2AP.E2AP_PDU_Descriptions.E2AP_PDU
        pdu.set_val(
            ('initiatingMessage', {
                "procedureCode": 4,   # RIC Control
                "criticality": "reject",
                "value": (
                    "RICcontrolRequest",
                    {
                        "protocolIEs": [
                            {
                                "id": 29,  # id-RICrequestID (E2AP v3)
                                "criticality": "reject",
                                "value": ("RICrequestID", {
                                    "ricRequestorID": random.randint(1, 65535),
                                    "ricInstanceID": random.randint(1, 65535),
                                })
                            },
                            {
                                "id": 5,   # id-RANfunctionID
                                "criticality": "reject",
                                "value": ("RANfunctionID", ran_function_id)
                            },
                            {
                                "id": 22,  # id-RICcontrolHeader
                                "criticality": "reject",
                                "value": ("RICcontrolHeader", header_bytes)
                            },
                            {
                                "id": 23,  # id-RICcontrolMessage
                                "criticality": "reject",
                                "value": ("RICcontrolMessage", message_bytes)
                            },
                            {
                                "id": 21,  # id-RICcontrolAckRequest
                                "criticality": "ignore",
                                "value": ("RICcontrolAckRequest", "ack")
                            },
                        ]
                    }
                )
            })
        )
        payload = pdu.to_aper()
        logger.info(f"[ASN1] E2AP ControlRequest encoded ({len(payload)}B)")
        return payload
    except Exception as e:
        logger.error(f"[ASN1] E2AP ControlRequest encode failed: {e}")
        return b''


# --- Test

if __name__ == "__main__":
    print("=== Test ASN.1 Codec ===")
    ev = encode_kpm_event_trigger(1000)
    print(f"EventTrigger: {ev.hex() if ev else 'FAILED'}")

    act = encode_kpm_action_definition(DRL_METRICS, 1000)
    print(f"ActionDef: {act.hex()[:60]}... ({len(act)}B)" if act else "FAILED")

    hdr = encode_rc_control_header(ue_id=42, ric_style_type=2, control_action_id=6)
    msg = encode_rc_control_message(prb_min=5, prb_max=80, sst=1, sd=0x000099)
    print(f"RC Header: {hdr.hex()} ({len(hdr)}B)")
    print(f"RC Message: {msg.hex()} ({len(msg)}B)")

    ctrl = encode_e2ap_control_request(3, hdr, msg)
    print(f"E2AP Control: {ctrl.hex()[:60]}... ({len(ctrl)}B)" if ctrl else "FAILED")
