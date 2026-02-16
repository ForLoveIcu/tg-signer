FROM python:3.12-slim-bookworm AS builder

RUN apt-get update && apt-get install -y gcc && \
    mkdir -p build && \
    pip wheel -w build tgcrypto

FROM python:3.12-slim

ARG TZ=Asia/Shanghai
ENV TZ=${TZ}
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=builder /build/*.whl /tmp/

RUN apt-get update && \
    apt-get install -y --no-install-recommends tzdata curl unzip && \
    ln -snf /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo ${TZ} > /etc/timezone && \
    XRAY_VERSION="v25.1.30" && \
    ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64) XRAY_ARCH="64" ;; \
        arm64) XRAY_ARCH="arm64-v8a" ;; \
        *) XRAY_ARCH="64" ;; \
    esac && \
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" -o /tmp/xray.zip && \
    unzip /tmp/xray.zip xray -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/xray && \
    rm -f /tmp/xray.zip && \
    apt-get purge -y curl unzip && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY . /src
RUN pip install /tmp/*.whl && \
    pip install "/src[speedup,db,gui]" && \
    rm -rf /src

WORKDIR /opt/tg-signer
