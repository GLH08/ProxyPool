# ProxyPool 代理池

基于 sing-box 的高性能代理池服务，支持多种协议，自动测速切换，提供 Web UI 和 RESTful API。

## 功能特点

- 支持多种协议：SS、VMess、VLESS、Trojan、Hysteria2
- 支持 HTTP/SOCKS 代理源（在线/本地）
- 自动测速，按延迟排序选择最优节点
- 智能切换，从 Top N 低延迟节点中随机选择
- Web UI 控制台，实时监控节点状态
- RESTful API，方便集成自动化脚本
- Docker 一键部署

## 快速开始

### Docker 部署（推荐）

```bash
# 克隆项目
git clone https://github.com/yourname/ProxyPool.git
cd ProxyPool

# 编辑订阅配置
vim subscriptions.txt  # 每行一个订阅 URL

# 启动服务
docker compose up -d

# 查看日志
docker compose logs -f
```

### 配置文件

**subscriptions.txt** - 订阅源（每行一个 URL）
```
https://your-subscription-url-1
https://your-subscription-url-2
```

**proxy_sources.txt** - HTTP/SOCKS 代理源（可选）
```
# 在线代理源（每日更新时拉取）
https://example.com/proxies.txt

# 本地文件
file:///app/my_proxies.txt
```

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| LISTEN_PORT | 10710 | 代理监听端口 |
| WEB_PORT | 8080 | Web UI 端口 |
| TOP_N_NODES | 50 | 参与切换的低延迟节点数 |
| INTERVAL_SECONDS | 1800 | 节点更新间隔（秒） |
| AUTO_SWITCH_INTERVAL | 0 | 自动切换间隔（秒，0=禁用） |

## 使用方法

### Web UI

访问 `http://YOUR_IP:8080` 查看控制台

### API 接口

| 接口 | 说明 |
|------|------|
| GET /api/switch | 随机切换节点 |
| GET /api/switch/<tag> | 切换到指定节点 |
| GET /api/test | 测试代理出口 IP |
| GET /api/nodes | 获取所有可用节点 |
| GET /api/top | 获取 Top N 节点 |
| GET /api/status | 获取系统状态 |
| GET /api/speedtest/<tag> | 测试节点下载速度 |
| GET /api/reload | 手动重新加载节点 |

### 代理使用

```bash
# 切换节点
curl http://YOUR_IP:8080/api/switch

# 使用代理
curl -x http://YOUR_IP:10710 https://api.ipify.org

# Python 示例
import requests

API = "http://YOUR_IP:8080"
PROXY = {"http": "http://YOUR_IP:10710", "https": "http://YOUR_IP:10710"}

# 切换后请求
requests.get(f"{API}/api/switch")
r = requests.get("https://api.ipify.org", proxies=PROXY)
print(r.text)
```

## 项目结构

```
ProxyPool/
├── scheduler.py          # 主调度器
├── subscription_parser.py # 订阅解析器
├── subscriptions.txt     # 订阅配置
├── proxy_sources.txt     # 代理源配置
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## License

MIT
