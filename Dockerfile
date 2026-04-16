FROM python:3.11-slim

WORKDIR /app

ARG TARGETARCH
ARG TARGETVARIANT
ARG SINGBOX_VERSION=1.10.1

# 设置时区为上海
ENV TZ=Asia/Shanghai
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl ca-certificates git jq tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# 下载与当前目标平台匹配的 sing-box
RUN set -eux; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
        amd64) singbox_arch='amd64' ;; \
        arm64) singbox_arch='arm64' ;; \
        armv7) singbox_arch='armv7' ;; \
        armv6) singbox_arch='armv6' ;; \
        *) echo "Unsupported sing-box architecture: ${TARGETARCH}${TARGETVARIANT}" >&2; exit 1 ;; \
    esac; \
    singbox_package="sing-box-${SINGBOX_VERSION}-linux-${singbox_arch}.tar.gz"; \
    wget -q "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${singbox_package}" -O /tmp/sing-box.tar.gz; \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp; \
    mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-${singbox_arch}/sing-box" /usr/local/bin/sing-box \
    && chmod +x /usr/local/bin/sing-box \
    && rm -rf /tmp/sing-box.tar.gz "/tmp/sing-box-${SINGBOX_VERSION}-linux-${singbox_arch}"

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件
COPY scheduler.py subscription_parser.py ./
COPY templates/ ./templates/

RUN mkdir -p /app/config

ENV SINGBOX_BINARY=/usr/local/bin/sing-box
ENV LISTEN_PORT=10710
ENV INTERVAL_SECONDS=1800
ENV WEB_PORT=8080
ENV ENABLE_WEB_UI=true
ENV MAX_NODES=500

EXPOSE 10710 8080

CMD ["python", "-u", "scheduler.py"]
