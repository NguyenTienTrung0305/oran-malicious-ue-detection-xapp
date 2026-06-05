FROM python:3.8-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libsctp-dev \
        wget \
    && rm -rf /var/lib/apt/lists/*

ARG RMR_VER=4.8.0
RUN wget -q --content-disposition \
        https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rmr_${RMR_VER}_amd64.deb/download.deb \
        -O /tmp/rmr.deb \
    && wget -q --content-disposition \
        https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rmr-dev_${RMR_VER}_amd64.deb/download.deb \
        -O /tmp/rmr-dev.deb \
    && dpkg -i /tmp/rmr.deb /tmp/rmr-dev.deb \
    && rm /tmp/rmr.deb /tmp/rmr-dev.deb

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.8-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libsctp1 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# RMR library
COPY --from=builder /usr/local/lib/librmr_si.so* /usr/local/lib/
RUN ldconfig

# Python packages
COPY --from=builder /root/.local /root/.local

WORKDIR /app
COPY src/ ./src/
COPY config/ /config/
COPY e2sm-v5.00.asn e2sm-rc-v5.00.asn /app/

COPY drl_v7_3_3_nue.zip /tmp/drl_model.zip

ENV PATH=/root/.local/bin:$PATH \
    LD_LIBRARY_PATH=/usr/local/lib \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    CONFIG_FILE=/config/config-file.json \
    RMR_SEED_RT=/config/uta_rtg.rt \
    RMR_RTG_SVC=service-ricplt-rtmgr-rmr.ricplt:4561 \
    DBAAS_SERVICE_HOST=service-ricplt-dbaas-tcp.ricplt \
    DBAAS_SERVICE_PORT=6379 \
    XAPP_NAME=my-xapp \
    LOG_LEVEL=INFO \
    KPM_REPORT_PERIOD_MS=1024 \
    KPM_GRANULARITY_MS=1000 \
    KPM_METRIC_GROUP=drl_malicious_ue \
    KPM_STYLE=5 \
    KPM_UE_IDS=0,1 \
    DRL_ENABLED=true \
    DRL_MODEL_PATH=/tmp/drl_model \
    DRL_VERSION=v7_3_3_nue \
    DRL_EVAL_MODE=0 \
    DATA_LOG_ENABLED=0 \
    GNB_WAIT_TIMEOUT=120 \
    ROUTE_WAIT_SECS=60 \
    TEST_CONTROL_ON_STARTUP=0 \
    TEST_CONTROL_DELAY_S=30 \
    TEST_CONTROL_UE_ID=1 \
    UE_SLICE_MAP="0:1/000001,1:1/000001"

EXPOSE 4560/tcp 4561/tcp 8088/tcp

CMD ["python3", "/app/src/xapp.py"]
