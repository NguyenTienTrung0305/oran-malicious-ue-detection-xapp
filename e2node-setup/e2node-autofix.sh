#!/bin/bash
echo "========================================"
echo "    E2NODE AUTO-FIX & PREP SCRIPT       "
echo "========================================"

echo "[0/6] Quét sạch các tiến trình cũ và giải phóng Socket..."
sudo pkill -9 srsue 2>/dev/null
sudo pkill -9 gnb 2>/dev/null
sleep 2

echo "[1/6] Đảm bảo MongoDB đang chạy..."
sudo systemctl start mongod

echo "[2/6] Khởi động NRF và SCP (Bộ não giao tiếp nội bộ)..."
sudo systemctl start open5gs-nrfd open5gs-scpd
sleep 2

echo "[3/6] Khởi động toàn bộ Mạng lõi Open5GS..."
sudo systemctl start open5gs-udrd open5gs-udmd open5gs-ausfd open5gs-pcfd open5gs-nssfd \
                     open5gs-bsfd open5gs-smfd open5gs-upfd open5gs-amfd
sleep 3


echo "[4/6] Kiểm tra AMF & UPF (User Plane)..."
for service in amfd upfd; do
    if ! systemctl is-active --quiet open5gs-$service; then
        echo " [!] $service chưa chạy, đang cố gắng kích hoạt..."
        sudo systemctl restart open5gs-$service
    fi
done


echo "[5/6] Làm mới Network Namespaces (ue1, ue2)..."
for NS in ue1 ue2; do
    sudo ip netns delete $NS 2>/dev/null
    sudo ip netns add $NS
    sudo ip netns exec $NS ip link set lo up
done
