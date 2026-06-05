#!/bin/bash
pkill -9 -f 'iperf3 -c' 2>/dev/null; pkill -f 'ping.*10.45' 2>/dev/null; sleep 2
ip netns exec ue1 iperf3 -c 10.45.0.1 -p 5201 -u -b 700K -t 135 > /tmp/c_ue0_victim.log 2>&1 &
ip netns exec ue2 iperf3 -c 10.45.0.1 -p 5202 -u -b 700K -t 35 > /tmp/c_ue1_light.log 2>&1 &
P1L=$!
echo "$(date +%s.%N) PHASE1_LIGHT_BOTH_700K" > /tmp/phase_marks.log
sleep 37
kill -9 $P1L 2>/dev/null; sleep 1
echo "$(date +%s.%N) PHASE2_ATTACK_HEAVY" >> /tmp/phase_marks.log
ip netns exec ue2 iperf3 -c 10.45.0.1 -p 5202 -u -b 50M -P 4 -t 95 > /tmp/c_ue1_attack.log 2>&1 &
wait %1 2>/dev/null
sleep 95
echo "$(date +%s.%N) STOP_ALL" >> /tmp/phase_marks.log
pkill -9 -f 'iperf3 -c' 2>/dev/null
