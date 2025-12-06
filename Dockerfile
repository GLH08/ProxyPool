FROM python:3.11-slim

WORKDIR /app

# 设置时区为上海
ENV TZ=Asia/Shanghai
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl ca-certificates git jq tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# 下载 sing-box
ARG SINGBOX_VERSION=1.10.1
RUN wget -q https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz \
    && tar -xzf sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz \
    && mv sing-box-${SINGBOX_VERSION}-linux-amd64/sing-box /usr/local/bin/sing-box \
    && chmod +x /usr/local/bin/sing-box \
    && rm -rf sing-box-${SINGBOX_VERSION}-linux-amd64*

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件
COPY scheduler.py subscription_parser.py ./

RUN mkdir -p /app/config

ENV SINGBOX_BINARY=/usr/local/bin/sing-box
ENV LISTEN_PORT=10710
ENV INTERVAL_SECONDS=1800
ENV WEB_PORT=8080
ENV ENABLE_WEB_UI=true
ENV MAX_NODES=500

EXPOSE 10710 8080

CMD ["python", "-u", "scheduler.py"]
