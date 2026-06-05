#!/bin/bash
# Chạy 20 scenarios liên tiếp — tổng ~5 giờ.
# Output: ~/kpm_data/raw.csv + labels.csv + scenarios.log
#
# Recommend chạy với nohup để không bị mất khi terminal đóng:
#   nohup ./run_all_20.sh > /tmp/all_20.log 2>&1 &
#   tail -f /tmp/all_20.log    # theo dõi tiến độ

set -uo pipefail
cd "$(dirname "$0")"

echo "=== Reset old data ==="
rm -f ~/kpm_data/labels.csv ~/kpm_data/raw.csv ~/kpm_data/scenarios.log
echo "Start time: $(date)"

# ─── 3 NORMAL ───
./run_scenario.sh "01_both_idle"          idle    idle    0 0
./run_scenario.sh "02_both_light"         light   light   0 0
./run_scenario.sh "03_both_medium"        medium  medium  0 0

# ─── DDoS volume — UE1 ───
./run_scenario.sh "04_ue1_ddos_heavy"     heavy   light   0 1
./run_scenario.sh "05_ue1_ddos_alone"     heavy   idle    0 1

# ─── DDoS volume — UE0 ───
./run_scenario.sh "06_ue0_ddos_heavy"     light   heavy   1 0
./run_scenario.sh "07_ue0_ddos_alone"     idle    heavy   1 0

# ─── Mining (sustained constant) ───
./run_scenario.sh "08_ue1_mining"         mining  light   0 1
./run_scenario.sh "09_ue0_mining"         light   mining  1 0

# ─── Burst (intermittent) ───
./run_scenario.sh "10_ue1_burst"          burst   light   0 1
./run_scenario.sh "11_ue0_burst"          light   burst   1 0

# ─── Low-and-slow ───
./run_scenario.sh "12_ue1_lowslow"        lowslow light   0 1
./run_scenario.sh "13_ue0_lowslow"        light   lowslow 1 0

# ─── Beaconing ───
./run_scenario.sh "14_ue1_beacon"         beacon  light   0 1
./run_scenario.sh "15_ue0_beacon"         light   beacon  1 0

# ─── Stealth rampup ───
./run_scenario.sh "16_ue1_rampup"         rampup  light   0 1

# ─── Exfiltration ───
./run_scenario.sh "17_ue1_exfil"          exfil   light   0 1

# ─── Edge cases ───
./run_scenario.sh "18_both_attack"        heavy   heavy   1 1
./run_scenario.sh "19_ue1_burst_ue0_med"  burst   medium  0 1
./run_scenario.sh "20_ue1_lowslow_ue0_heavy" lowslow heavy 1 1

# ─── Finalize ───
echo ""
echo "=== ALL 20 SCENARIOS DONE — finalizing ==="
./finalize_data.sh

# Big completion bell
for i in 1 2 3 4 5; do printf '\a'; sleep 0.3; done
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  🎉  TẤT CẢ XONG — Upload labeled.csv lên Kaggle để train     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "End time: $(date)"
