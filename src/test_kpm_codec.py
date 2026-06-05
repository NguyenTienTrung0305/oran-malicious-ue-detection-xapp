#!/usr/bin/env python3
"""
Test ASN.1 codec functions.
Chạy: python3 test_kpm_codec.py
"""

import sys
import traceback


def test_metric_groups():
    from asn1_codec import (
        SRSRAN_KPM_METRICS, DRL_METRICS, METRIC_GROUPS,
        get_metrics_for_group,
    )

    assert len(SRSRAN_KPM_METRICS) == 15, f"Expected 15, got {len(SRSRAN_KPM_METRICS)}"
    assert len(DRL_METRICS) == 10, f"Expected 10, got {len(DRL_METRICS)}"

    # All DRL metrics must be in SRSRAN list
    for m in DRL_METRICS:
        assert m in SRSRAN_KPM_METRICS, f"{m} not in SRSRAN_KPM_METRICS"

    # Test group lookup
    assert get_metrics_for_group("all") == SRSRAN_KPM_METRICS
    assert get_metrics_for_group("drl_malicious_ue") == DRL_METRICS
    assert len(get_metrics_for_group("prb")) == 6

    try:
        get_metrics_for_group("nonexistent")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

    print("[PASS] test_metric_groups")


def test_event_trigger_encoding():
    from asn1_codec import encode_kpm_event_trigger, REPORT_PERIOD_MAP

    # Test valid period
    result = encode_kpm_event_trigger(1024)
    assert len(result) > 0, "EventTrigger encoding returned empty"
    print(f"[PASS] EventTrigger 1024ms: {result.hex()} ({len(result)}B)")

    # Test auto-mapping (1000 → 1024)
    result2 = encode_kpm_event_trigger(1000)
    assert len(result2) > 0, "EventTrigger auto-map failed"
    print(f"[PASS] EventTrigger 1000ms→1024ms: {result2.hex()} ({len(result2)}B)")


def test_action_definition_encoding():
    from asn1_codec import encode_kpm_action_definition, DRL_METRICS

    result = encode_kpm_action_definition(DRL_METRICS, granularity_ms=1000)
    assert len(result) > 0, "ActionDef encoding returned empty"
    print(f"[PASS] ActionDef ({len(DRL_METRICS)} metrics): {len(result)}B")

    # Test single metric
    result2 = encode_kpm_action_definition(["DRB.UEThpDl"], granularity_ms=1000)
    assert len(result2) > 0, "ActionDef single metric failed"
    assert len(result2) < len(result), "Single metric should be smaller"
    print(f"[PASS] ActionDef (1 metric): {len(result2)}B")


def test_rc_encoding():
    from asn1_codec import (
        encode_rc_control_header,
        encode_rc_control_message,
        encode_e2ap_control_request,
    )

    hdr = encode_rc_control_header(ric_style_type=2, control_action_id=1)
    assert len(hdr) == 4, f"RC header should be 4B, got {len(hdr)}"

    msg = encode_rc_control_message(
        prb_min=5, prb_max=80, prb_ded=0, sst=1, sd=0x000099,
    )
    assert len(msg) > 0, "RC message empty"

    e2ap = encode_e2ap_control_request(3, hdr, msg)
    assert len(e2ap) > 0, "E2AP control request empty"
    print(f"[PASS] RC: hdr={len(hdr)}B msg={len(msg)}B e2ap={len(e2ap)}B")


def test_kpm_decode_empty():
    from asn1_codec import decode_kpm_indication, DRL_METRICS

    result = decode_kpm_indication(b"", b"", metric_names=DRL_METRICS)
    assert "measurements" in result
    assert len(result["measurements"]) == len(DRL_METRICS)
    # All should be 0 (default)
    for name in DRL_METRICS:
        assert result["measurements"][name] == 0
    print("[PASS] KPM decode empty (defaults to 0)")


def main():
    tests = [
        test_metric_groups,
        test_event_trigger_encoding,
        test_action_definition_encoding,
        test_rc_encoding,
        test_kpm_decode_empty,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"[FAIL] {test.__name__}: {e}")
            traceback.print_exc()

    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
