#!/bin/bash
# Startup script cho e2node sau khi resume VM
# run: sudo bash ~/startup_e2node.sh

echo "=== [1] Kill old processes ==="
pkill -9 -f zmq_broker 2>/dev/null || true
pkill -9 -f "gnb/gnb"  2>/dev/null || true
pkill -9 -f srsue       2>/dev/null || true
sleep 2

echo "=== [2] Open5GS + netns ==="
bash /home/nttrung/e2node-autofix.sh 2>&1 | tail -5

echo "=== [3] ZMQ Broker ==="
nohup python3 /home/nttrung/zmq_broker.py > /tmp/broker.log 2>&1 &
echo "Broker started"
sleep 3

echo "=== [4] gNB ==="
rm -f /tmp/gnb.log /tmp/gnb_stdout.log
nohup /home/nttrung/srsRAN_Project/build/apps/gnb/gnb -c /home/nttrung/gnb_zmq.yml > /tmp/gnb_stdout.log 2>&1 &
echo "gNB started, waiting 12s for E2 Setup..."
sleep 12
grep -q "E2 Setup procedure successful" /tmp/gnb.log 2>/dev/null && echo "E2 Setup OK" || echo "E2 Setup chua xong!"

echo "=== [5] UE1 + UE2 ==="
rm -f /tmp/ue1_stdout.log /tmp/ue2_stdout.log
nohup /home/nttrung/srsRAN_4G/build/srsue/src/srsue /home/nttrung/ue1_zmq.conf > /tmp/ue1_stdout.log 2>&1 &
sleep 15
nohup /home/nttrung/srsRAN_4G/build/srsue/src/srsue /home/nttrung/ue2_zmq.conf > /tmp/ue2_stdout.log 2>&1 &
echo "UEs started, waiting 45s..."
sleep 45
ip netns exec ue1 ip -br a 2>/dev/null || echo "ue1: no IP"
ip netns exec ue2 ip -br a 2>/dev/null || echo "ue2: no IP"
echo "Done! Tren ric-master: kubectl -n ricxapp rollout restart deploy/ricxapp-my-xapp"
