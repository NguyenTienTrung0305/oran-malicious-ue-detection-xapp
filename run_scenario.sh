#!/bin/bash
#
# Usage:  ./run_scenario.sh <name> <ue1_pattern> <ue2_pattern> <label_ue0> <label_ue1> [duration_sec]
#
# Patterns:
#   idle     no traffic
#   light    -i 0.5 -s 600     ~10 kbps  (browsing nhẹ)
#   medium   -i 0.2 -s 1200    ~50 kbps  (browsing thường)
#   heavy    -f   -s 1450      flood     (DDoS volume)
#   mining   -i 0.15 -s 600    ~30 kbps  (sustained constant)
#   burst    flood 30s ↔ idle 30s        (DDoS intermittent — evade)
#   lowslow  -i 2 -s 200       ~1 kbps   (slow-loris — low rate persistent)
#   beacon   -i 5 -s 100       ~0.2 kbps (C&C botnet — periodic small)
#   rampup   light→medium→heavy           (stealth — tăng dần)
#   exfil    -i 0.05 -s 1450 + bigger UL  (upload heavy — exfil/mining)
#
# Examples:
#   ./run_scenario.sh "01_both_idle"        idle     idle    0 0
#   ./run_scenario.sh "13_ue1_burst"        burst    light   0 1
#   ./run_scenario.sh "14_ue1_lowslow"      lowslow  light   0 1
#   ./run_scenario.sh "15_ue1_beacon"       beacon   light   0 1

set -uo pipefail

NAME=${1:?"missing scenario name"}
P_UE1=${2:?"missing ue1 pattern"}
P_UE2=${3:?"missing ue2 pattern"}
L_UE0=${4:?"missing label_ue0 (0|1)"}
L_UE1=${5:?"missing label_ue1 (0|1)"}
DUR=${6:-900}

E2NODE_HOST="yourip"
E2NODE_PASS="yourpass"
DATA_DIR="$HOME/kpm_data"
mkdir -p "$DATA_DIR"

ssh_e2() { sshpass -p "$E2NODE_PASS" ssh -o StrictHostKeyChecking=no "$E2NODE_HOST" "$@"; }

# Generate launcher script content for a UE
make_launcher() {
  local pattern=$1
  local ns=$2
  case $pattern in
    idle)
      echo ":"
      ;;
    light)
      echo "ip netns exec $ns ping -i 0.5 -s 600 10.45.0.1 > /dev/null 2>&1 < /dev/null &"
      ;;
    medium)
      echo "ip netns exec $ns ping -i 0.2 -s 1200 10.45.0.1 > /dev/null 2>&1 < /dev/null &"
      ;;
    heavy)
      echo "ip netns exec $ns ping -f -s 1450 10.45.0.1 > /dev/null 2>&1 < /dev/null &"
      ;;
    mining)
      echo "ip netns exec $ns ping -i 0.15 -s 600 10.45.0.1 > /dev/null 2>&1 < /dev/null &"
      ;;
    burst)
      # Alternating 30s flood / 30s idle, controlled via wrapper script
      cat <<EOF
nohup bash -c '
while true; do
  ip netns exec $ns ping -f -s 1450 -w 30 10.45.0.1 > /dev/null 2>&1
  sleep 30
done
' > /dev/null 2>&1 < /dev/null &
EOF
      ;;
    lowslow)
      # Slow-loris-like: very slow but persistent
      echo "ip netns exec $ns ping -i 2 -s 200 10.45.0.1 > /dev/null 2>&1 < /dev/null &"
      ;;
    beacon)
      # C&C beaconing: small packet every 5s
      echo "ip netns exec $ns ping -i 5 -s 100 10.45.0.1 > /dev/null 2>&1 < /dev/null &"
      ;;
    rampup)
      # Stealth: light(180s) → medium(180s) → heavy(rest)
      cat <<EOF
nohup bash -c '
ip netns exec $ns ping -i 0.5 -s 600 -w 180 10.45.0.1 > /dev/null 2>&1
ip netns exec $ns ping -i 0.2 -s 1200 -w 180 10.45.0.1 > /dev/null 2>&1
ip netns exec $ns ping -f -s 1450 10.45.0.1 > /dev/null 2>&1
' > /dev/null 2>&1 < /dev/null &
EOF
      ;;
    exfil)
      # Upload-heavy: high frequency big packets (cả UL + DL nhưng nặng UL volume)
      echo "ip netns exec $ns ping -i 0.05 -s 1450 10.45.0.1 > /dev/null 2>&1 < /dev/null &"
      ;;
    *)
      echo "BAD_PATTERN_$pattern" >&2
      exit 1
      ;;
  esac
}

CMD_UE1=$(make_launcher "$P_UE1" ue1)
CMD_UE2=$(make_launcher "$P_UE2" ue2)

clear
cat <<EOF
Scenario: $NAME
UE1 (netns ue1, F1AP=1): $P_UE1   (label=$L_UE1)
UE0 (netns ue2, F1AP=0): $P_UE2   (label=$L_UE0)
Duration: ${DUR}s ($((DUR/60)) min)
EOF

# Stop any old traffic — write killer script first, then sudo run
ssh_e2 "cat > /tmp/kill_sc.sh <<'KEOF'
#!/bin/bash
pkill -f 'ping.*10.45.0' 2>/dev/null
pkill -f 'while true' 2>/dev/null
sleep 1
KEOF
chmod +x /tmp/kill_sc.sh
echo $E2NODE_PASS | sudo -S /tmp/kill_sc.sh" || true

START_TS=$(($(date +%s) * 1000))


SCRIPT_CONTENT="#!/bin/bash
$CMD_UE1
$CMD_UE2
"
ssh_e2 "cat > /tmp/sc.sh && chmod +x /tmp/sc.sh && echo $E2NODE_PASS | sudo -S /tmp/sc.sh" <<< "$SCRIPT_CONTENT"

echo ""
echo "[$(date +%H:%M:%S)] Traffic started — đang collect data ${DUR}s..."
echo ""

# Progress bar
for i in $(seq 1 $((DUR/60))); do
  sleep 60
  printf "."
  if (( i % 5 == 0 )); then
    printf " %dmin/%dmin\n" "$i" "$((DUR/60))"
  fi
done
sleep $((DUR % 60))

END_TS=$(($(date +%s) * 1000))

# Stop traffic — reuse killer script
ssh_e2 "echo $E2NODE_PASS | sudo -S /tmp/kill_sc.sh" || true

# Write label window
echo "${START_TS},${END_TS},${NAME},${L_UE0},${L_UE1}" >> "$DATA_DIR/labels.csv"

# Pull current CSV snapshot
POD=$(kubectl -n ricxapp get pods -l app=ricxapp-my-xapp -o jsonpath='{.items[0].metadata.name}')
kubectl -n ricxapp cp "$POD:/tmp/kpm_log.csv" "$DATA_DIR/raw.csv" 2>&1 | tail -1
ROWS=$(wc -l < "$DATA_DIR/raw.csv" 2>/dev/null || echo 0)

echo ""
echo ""
printf '\a'; sleep 0.2; printf '\a'; sleep 0.2; printf '\a'
cat <<EOF
DONE: $NAME
Window: $START_TS  →  $END_TS  (${DUR}s)
Total rows in raw.csv: $ROWS
Labels file: $DATA_DIR/labels.csv ($(wc -l < $DATA_DIR/labels.csv) scenarios)

EOF
