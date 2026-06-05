#!/bin/bash
# Build Docker image, push to registry, onboard + install xApp via dms_cli
set -e

# Docker registry độc lập với Kubernets, là container docker được build từ image registry:2 
# local image được push lên registry này, rồi ChartMuseum sẽ pull về khi onboard xApp
REGISTRY="192.168.159.100:5000"
XAPP_NAME="my-xapp"
VERSION="${1:-1.0.0}"
IMAGE="${REGISTRY}/${XAPP_NAME}:${VERSION}"
CONFIG_DIR="$(cd "$(dirname "$0")/config" && pwd)"

export CHART_REPO_URL="${CHART_REPO_URL:-http://localhost:8879}"

echo "============================================"
echo "  Build & Deploy: ${XAPP_NAME} v${VERSION}"
echo "  ChartMuseum: ${CHART_REPO_URL}"
echo "============================================"

# -- Step 1: Build Docker image
echo ""
echo "[1/4] Building Docker image: ${IMAGE}"
cd "$(dirname "$0")"
docker build -t "${IMAGE}" .

# --- Step 2: Push to registry
echo ""
echo "[2/4] Pushing to registry: ${REGISTRY}"
docker push "${IMAGE}"

# --- Step 3: Onboard xApp (dms_cli -> ChartMuseum)
echo ""
echo "[3/4] Onboarding xApp via dms_cli..."
# NOTE: --shcema_file_path là typo gốc trong dms_cli
dms_cli onboard \
    --config_file_path="${CONFIG_DIR}/config-file.json" \
    --shcema_file_path="${CONFIG_DIR}/schema.json"

echo "Waiting 5s for ChartMuseum to sync..."
sleep 5

# --- Step 4: Install xApp
echo ""
echo "[4/4] Installing xApp..."
dms_cli install \
    --xapp_chart_name="${XAPP_NAME}" \
    --version="${VERSION}" \
    --namespace=ricxapp

echo ""
echo "============================================"
echo "  Deploy complete!"
echo "============================================"
echo "Command deploy cd ~/my-xapp && bash build_and_deploy.sh 1.0.1"
echo "Check status:  kubectl get pods -n ricxapp"
echo "Logs:          kubectl logs -n ricxapp -l app=ricxapp-${XAPP_NAME} -f"
echo "Uninstall:     dms_cli uninstall --xapp_chart_name=${XAPP_NAME} --namespace=ricxapp"
echo "Quick Update: docker build --no-cache -t 192.168.159.100:5000/my-xapp:1.0.1 . \ docker push 192.168.159.100:5000/my-xapp:1.0.1 \ kubectl delete pod -n ricxapp -l app=ricxapp-my-xapp"
