# ProxyPool 代理池

基于 sing-box 的高性能代理池服务，支持多种协议，自动测速切换，提供 Web UI 和 RESTful API。

[![Build](https://github.com/GLH08/ProxyPool/actions/workflows/docker.yml/badge.svg)](https://github.com/GLH08/ProxyPool/actions/workflows/docker.yml)
[![Docker Image](https://img.shields.io/badge/ghcr.io-glh08%2Fproxypool-blue)](https://ghcr.io/glh08/proxypool)

## 功能特点

- 🚀 支持多种协议：SS、VMess、VLESS、Trojan、Hysteria2
- 🌐 支持 HTTP/SOCKS 代理源（在线/本地）
- ⚡ 自动测速，按延迟排序选择最优节点
- 🔄 智能切换，从 Top N 低延迟节点中随机选择（自动排除当前节点）
- 🖥️ Web UI 控制台，实时监控节点状态，支持节点搜索
- 🔌 RESTful API，方便集成自动化脚本
- 🐳 Docker 一键部署，支持 GHCR 镜像
- 🔁 sing-box 崩溃自动重启
- 📡 健康检查 API，真正测试代理可用性

## 快速开始

### 方式一：从 GHCR 拉取镜像（推荐）

```bash
# 创建目录
mkdir proxy-pool && cd proxy-pool

# 下载配置文件
curl -O https://raw.githubusercontent.com/GLH08/ProxyPool/main/docker-compose.prod.yml
curl -O https://raw.githubusercontent.com/GLH08/ProxyPool/main/subscriptions.txt
curl -O https://raw.githubusercontent.com/GLH08/ProxyPool/main/proxy_sources.txt

# ⚠️ 必须：添加你的订阅链接（至少一个）
vim subscriptions.txt  # 每行一个订阅 URL

# 启动服务
docker compose -f docker-compose.prod.yml up -d

# 查看日志
docker compose -f docker-compose.prod.yml logs -f
```

> **注意**：`subscriptions.txt` 默认为空（仅包含注释），启动前必须添加至少一个有效的订阅链接，否则代理池将无可用节点。

### 方式二：从源码构建

```bash
# 克隆项目
git clone https://github.com/GLH08/ProxyPool.git
cd ProxyPool

# ⚠️ 必须：添加你的订阅链接（至少一个）
vim subscriptions.txt  # 每行一个订阅 URL

# 启动服务
docker compose up -d

# 查看日志
docker compose logs -f
```

## 配置说明

### subscriptions.txt - 订阅源（必填）

每行一个订阅 URL，支持：
- Clash YAML 订阅
- V2Ray/SS/Trojan 订阅链接（base64 编码或明文）
- Hysteria2 订阅

```
# 示例格式（请替换为你自己的订阅链接）
https://your-airport.com/api/v1/client/subscribe?token=xxx
https://example.com/clash.yaml
# 注释行会被忽略
```

> **重要**：此文件默认为空模板，必须添加你自己的订阅链接才能使用。

### proxy_sources.txt - HTTP/SOCKS 代理源（可选）

```
# 格式: type|url 或直接 url（自动检测类型）
http|https://example.com/http.txt
socks5|https://example.com/socks5.txt
```

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `LISTEN_PORT` | 10710 | 代理监听端口 |
| `WEB_PORT` | 8080 | Web UI 端口 |
| `TOP_N_NODES` | 50 | 参与切换的低延迟节点数 |
| `INTERVAL_SECONDS` | 1800 | 节点更新间隔（秒） |
| `AUTO_SWITCH_INTERVAL` | 0 | 自动切换间隔（秒，0=禁用） |
| `MAX_NODES` | 500 | 最大节点数量 |
| `VERIFY_HTTP_PROXIES` | true | 是否验证 HTTP 代理可用性 |
| `ENABLE_ONLINE_SOURCES` | false | 是否启用在线代理源 |

## 使用方法

### Web UI

访问 `http://YOUR_IP:8080` 查看控制台

功能：
- 📊 概览：节点统计、当前节点、请求日志
- 📋 节点列表：可用节点、延迟、属地、支持搜索
- 🏆 Top 节点：按延迟排序的最优节点
- 📝 日志：系统日志和请求日志
- 🔌 API 文档

### API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/switch` | GET/POST | 随机切换节点 |
| `/api/switch/<tag>` | GET/POST | 切换到指定节点 |
| `/api/test` | GET | 测试代理出口 IP |
| `/api/nodes` | GET | 获取所有可用节点及延迟 |
| `/api/top` | GET | 获取 Top N 节点 |
| `/api/node/<tag>` | GET | 获取节点配置（sing-box 格式） |
| `/api/status` | GET | 获取系统状态 |
| `/api/health` | GET | 健康检查（真正测试代理可用性） |
| `/api/request_logs` | GET | 获取请求日志 |
| `/api/speedtest/<tag>` | GET | 测试节点下载速度 |
| `/api/reload` | GET | 手动重新加载节点 |
| `/api/restart_singbox` | POST | 手动重启 sing-box |

### 代理使用示例

```bash
# 切换节点
curl http://YOUR_IP:8080/api/switch

# 使用代理访问
curl -x http://YOUR_IP:10710 https://api.ipify.org

# 健康检查
curl http://YOUR_IP:8080/api/health
```

```python
import requests

API = "http://YOUR_IP:8080"
PROXY = {"http": "http://YOUR_IP:10710", "https": "http://YOUR_IP:10710"}

# 切换节点后请求
requests.get(f"{API}/api/switch")
r = requests.get("https://api.ipify.org", proxies=PROXY)
print(f"出口 IP: {r.text}")

# 使用测试接口（自动切换 + 请求 + 记录日志）
r = requests.get(f"{API}/api/test?url=https://api.ipify.org")
print(r.json())
```

## 项目结构

```
ProxyPool/
├── .github/
│   └── workflows/
│       └── docker.yml        # GitHub Actions CI/CD
├── templates/
│   └── index.html            # Web UI 模板
├── scheduler.py              # 主调度器
├── subscription_parser.py    # 订阅解析器
├── subscriptions.txt         # 订阅配置
├── proxy_sources.txt         # 代理源配置
├── docker-compose.yml        # 开发/源码构建配置
├── docker-compose.prod.yml   # 生产环境配置（GHCR 镜像）
├── Dockerfile
├── requirements.txt
└── README.md
```

## Docker 镜像

镜像托管在 GitHub Container Registry (GHCR)：

```bash
# 拉取最新版本
docker pull ghcr.io/glh08/proxypool:latest

# 拉取指定版本
docker pull ghcr.io/glh08/proxypool:1.0.0

# 拉取指定分支
docker pull ghcr.io/glh08/proxypool:main
```

### 镜像标签说明

| 标签格式 | 说明 |
|----------|------|
| `latest` | main 分支最新版本 |
| `main` | main 分支 |
| `sha-abc1234` | 指定 commit |
| `1.2.3` | 语义化版本 |
| `1.2` | 主版本.次版本 |

## 定时任务

- **节点更新**：每 30 分钟（可配置）
- **定时全量更新**：每日 00:00 和 12:00（包含在线代理源）

## License

MIT
