#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理池调度器 - 使用 sing-box 作为代理后端
支持: ss, vmess, vless, trojan, hysteria2, http, socks
"""
import subprocess
import time
import signal
import sys
import os
import json
import random
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
from threading import Thread, Lock
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 上海时区 (UTC+8)
SHANGHAI_TZ = timezone(timedelta(hours=8))


def now_shanghai() -> datetime:
    """获取上海时区当前时间"""
    return datetime.now(SHANGHAI_TZ)


# 设置日志时区
class ShanghaiFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = now_shanghai()
        if datefmt:
            return ct.strftime(datefmt)
        return ct.strftime('%Y-%m-%d %H:%M:%S')


for handler in logging.root.handlers:
    handler.setFormatter(ShanghaiFormatter('[%(asctime)s] [%(levelname)s] %(message)s'))

try:
    from flask import Flask, jsonify, render_template_string, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


# ==================== 常量配置 ====================
@dataclass
class Config:
    """应用配置"""
    # 路径
    singbox_binary: str = os.environ.get('SINGBOX_BINARY', '/usr/local/bin/sing-box')
    config_path: Path = field(default_factory=lambda: Path('config/sing-box.json'))
    
    # 端口
    listen_port: int = int(os.environ.get('LISTEN_PORT', '10710'))
    web_port: int = int(os.environ.get('WEB_PORT', '8080'))
    clash_api_port: int = int(os.environ.get('CLASH_API_PORT', '9090'))
    
    # 功能开关
    enable_web_ui: bool = os.environ.get('ENABLE_WEB_UI', 'true').lower() == 'true'
    
    # 节点相关
    top_n_nodes: int = int(os.environ.get('TOP_N_NODES', '50'))
    max_display_proxies: int = 500  # 显示的最大代理数
    
    # 时间间隔（秒）
    interval_seconds: int = int(os.environ.get('INTERVAL_SECONDS', '1800'))
    auto_switch_interval: int = int(os.environ.get('AUTO_SWITCH_INTERVAL', '0'))
    
    # 日志
    max_logs: int = 500
    max_request_logs: int = 200
    
    # 并发
    speedtest_workers: int = 200
    ip_location_workers: int = 10
    ip_location_batch_size: int = 50
    
    # 超时（秒）
    api_timeout: int = 5
    proxy_test_timeout: int = 10
    speedtest_timeout: int = 30
    
    # 速度测试
    default_speedtest_url: str = "http://speedtest.tele2.net/5MB.zip"
    max_speedtest_size: int = 10 * 1024 * 1024  # 10MB
    
    # Web UI 刷新间隔（毫秒）
    web_refresh_interval: int = 10000


# 全局配置实例
CFG = Config()

# 兼容旧代码的常量别名
SINGBOX_BINARY = CFG.singbox_binary
LISTEN_PORT = CFG.listen_port
INTERVAL_SECONDS = CFG.interval_seconds
WEB_PORT = CFG.web_port
CLASH_API_PORT = CFG.clash_api_port
ENABLE_WEB_UI = CFG.enable_web_ui
TOP_N_NODES = CFG.top_n_nodes
AUTO_SWITCH_INTERVAL = CFG.auto_switch_interval
MAX_LOGS = CFG.max_logs
CONFIG_PATH = CFG.config_path


# ==================== 状态管理 ====================
@dataclass
class ProxyStatus:
    """代理池状态"""
    last_update: Optional[str] = None
    next_update: Optional[str] = None
    proxy_count: int = 0
    available_count: int = 0
    proxies: List[Dict] = field(default_factory=list)
    proxies_full: List[Dict] = field(default_factory=list)
    singbox_running: bool = False
    listen_port: int = CFG.listen_port
    update_interval: int = CFG.interval_seconds
    total_requests: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    logs: deque = field(default_factory=lambda: deque(maxlen=CFG.max_logs))
    request_logs: deque = field(default_factory=lambda: deque(maxlen=CFG.max_request_logs))
    current_node: Optional[str] = None
    speedtest_done: bool = False
    auto_switch_interval: int = CFG.auto_switch_interval


# 全局状态（保持字典格式兼容旧代码）
proxy_status = {
    'last_update': None,
    'next_update': None,
    'proxy_count': 0,
    'available_count': 0,
    'proxies': [],
    'proxies_full': [],
    'singbox_running': False,
    'listen_port': CFG.listen_port,
    'update_interval': CFG.interval_seconds,
    'total_requests': 0,
    'by_type': {},
    'logs': deque(maxlen=CFG.max_logs),
    'request_logs': deque(maxlen=CFG.max_request_logs),
    'current_node': None,
    'speedtest_done': False,
    'auto_switch_interval': CFG.auto_switch_interval,
}
status_lock = Lock()

# 缓存
ip_location_cache: Dict[str, str] = {}
speed_test_cache: Dict[str, Dict] = {}
delays_cache: Dict[str, Any] = {'data': {}, 'time': 0}  # 延迟缓存，30秒过期


def get_ip_location(ip: str) -> str:
    """查询 IP 属地（带缓存）"""
    if not ip or ip in ip_location_cache:
        return ip_location_cache.get(ip, '')
    
    try:
        import requests as req
        resp = req.get(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode",
            timeout=CFG.api_timeout
        )
        if resp.status_code == 200:
            data = resp.json()
            location = data.get('countryCode', '') or data.get('country', '')
            ip_location_cache[ip] = location
            return location
    except (req.RequestException, ValueError, KeyError):
        pass
    
    ip_location_cache[ip] = ''
    return ''


def batch_get_ip_locations(ips: List[str], wait: bool = False) -> None:
    """批量查询 IP 属地"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    new_ips = [ip for ip in ips if ip and ip not in ip_location_cache]
    if not new_ips:
        return
    
    # 增加批量大小
    new_ips = new_ips[:100]
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(get_ip_location, ip) for ip in new_ips]
        if wait:
            # 等待完成
            for f in as_completed(futures, timeout=10):
                try:
                    f.result()
                except:
                    pass


def test_node_speed(node_tag: str, test_url: Optional[str] = None) -> Dict[str, Any]:
    """测试节点的下载速度"""
    import requests as req
    import urllib3
    urllib3.disable_warnings()
    
    if not test_url:
        test_url = CFG.default_speedtest_url
    
    result = {
        'node': node_tag,
        'success': False,
        'download_speed': 0,  # MB/s
        'latency': 0,  # ms
        'test_url': test_url,
        'file_size': 0,  # bytes
        'time_taken': 0,  # seconds
    }
    
    # 先切换到指定节点
    if not switch_to_node(node_tag):
        result['error'] = 'Failed to switch node'
        return result
    
    proxy_url = f"http://127.0.0.1:{CFG.listen_port}"
    proxies = {'http': proxy_url, 'https': proxy_url}
    
    try:
        # 测试延迟
        start_latency = time.time()
        req.get("http://www.gstatic.com/generate_204", proxies=proxies, timeout=CFG.api_timeout, verify=False)
        result['latency'] = int((time.time() - start_latency) * 1000)
        
        # 测试下载速度
        start_time = time.time()
        resp = req.get(test_url, proxies=proxies, timeout=CFG.speedtest_timeout, verify=False, stream=True)
        
        total_size = 0
        for chunk in resp.iter_content(chunk_size=8192):
            total_size += len(chunk)
            if total_size > CFG.max_speedtest_size:
                break
        
        time_taken = time.time() - start_time
        
        result['success'] = True
        result['file_size'] = total_size
        result['time_taken'] = round(time_taken, 2)
        result['download_speed'] = round(total_size / time_taken / 1024 / 1024, 2) if time_taken > 0 else 0
        
        # 缓存结果
        speed_test_cache[node_tag] = {
            'speed': result['download_speed'],
            'latency': result['latency'],
            'time': now_shanghai().strftime('%H:%M:%S')
        }
        
    except req.RequestException as e:
        result['error'] = str(e)[:100]
    
    return result


def log(message, level='INFO'):
    timestamp = now_shanghai().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] [{level}] {message}"
    print(log_line, flush=True)
    with status_lock:
        proxy_status['logs'].append({'time': timestamp, 'level': level, 'msg': message})


def log_request(target: str, exit_ip: str, node: str, delay: int, client: str, method: str = 'api'):
    """记录请求日志"""
    timestamp = now_shanghai().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = {
        'time': timestamp,
        'target': target,
        'exit_ip': exit_ip,
        'node': node,
        'delay': delay,
        'client': client,
        'method': method
    }
    with status_lock:
        proxy_status['request_logs'].append(log_entry)
    # 同时输出到 docker 日志
    print(f"[{timestamp}] [REQUEST] {method} | {target} | {exit_ip} | {node} | {delay}ms | {client}", flush=True)


def generate_singbox_config(outbounds: list) -> dict:
    """生成 sing-box 配置，启用 Clash API 和详细日志"""
    tags = [ob['tag'] for ob in outbounds]
    
    config = {
        "log": {
            "level": "info",
            "timestamp": True,
            "output": ""  # 输出到 stdout
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"0.0.0.0:{CLASH_API_PORT}",
                "default_mode": "rule"
            }
        },
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "0.0.0.0",
            "listen_port": LISTEN_PORT,
            "sniff": True,
            "sniff_override_destination": False
        }],
        "outbounds": [
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": "http://www.gstatic.com/generate_204",
                "interval": "3m",
                "tolerance": 50
            },
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["auto"] + tags,
                "default": "auto"
            },
            {"type": "direct", "tag": "direct"}
        ] + outbounds,
        "route": {"rules": [], "final": "proxy"}
    }
    return config


def write_config(outbounds: list):
    config = generate_singbox_config(outbounds)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    log(f"配置已写入: {CONFIG_PATH}")


def run_singbox():
    try:
        log("启动 sing-box...")
        process = subprocess.Popen(
            [SINGBOX_BINARY, "run", "-c", str(CONFIG_PATH)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        proxy_status['singbox_running'] = True
        
        def read_logs():
            import re
            try:
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    # 输出所有 sing-box 日志到 docker logs
                    if 'error' in line.lower() or 'fatal' in line.lower():
                        log(f"[sing-box] {line[:200]}", 'ERROR')
                    # 解析连接日志并存储到 request_logs
                    # 格式: INFO [xxx] inbound/mixed[mixed-in]: connection to xxx.com:443
                    if 'connection' in line.lower() and ('inbound' in line.lower() or 'outbound' in line.lower()):
                        print(f"[PROXY] {line}", flush=True)
                        # 尝试解析目标地址
                        match = re.search(r'connection.*?to\s+([^\s:]+):?(\d+)?', line, re.IGNORECASE)
                        if match:
                            target = match.group(1)
                            port = match.group(2) or '443'
                            timestamp = now_shanghai().strftime('%Y-%m-%d %H:%M:%S')
                            with status_lock:
                                proxy_status['request_logs'].append({
                                    'time': timestamp,
                                    'target': f"{target}:{port}",
                                    'exit_ip': '-',
                                    'node': proxy_status.get('current_node', 'auto'),
                                    'delay': 0,
                                    'client': 'proxy',
                                    'method': 'CONNECT'
                                })
            except:
                pass
        
        Thread(target=read_logs, daemon=True).start()
        return process
    except Exception as e:
        log(f"启动 sing-box 失败: {e}", 'ERROR')
        proxy_status['singbox_running'] = False
        return None


def kill_singbox(process):
    if process:
        try:
            log("停止 sing-box...")
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        except:
            pass
        proxy_status['singbox_running'] = False


def collect_nodes():
    try:
        from subscription_parser import fetch_all_subscriptions
        
        log("开始获取订阅...")
        outbounds, stats = fetch_all_subscriptions()
        
        log(f"订阅结果: 成功={stats['ok']}, 失败={stats['failed']}, 节点={stats['nodes']} (去重前={stats.get('before_dedup', stats['nodes'])})")
        
        if stats.get('by_type'):
            types_str = ', '.join(f"{k}={v}" for k, v in stats['by_type'].items())
            log(f"节点类型: {types_str}")
        
        if outbounds:
            write_config(outbounds)
            with status_lock:
                proxy_status['proxy_count'] = len(outbounds)
                proxy_status['proxies'] = [
                    {'type': ob.get('type', 'unknown'), 'tag': ob.get('tag', ''), 
                     'server': ob.get('server', ''), 'port': ob.get('server_port', 0)}
                    for ob in outbounds[:500]
                ]
                proxy_status['proxies_full'] = outbounds  # 保存完整信息
                proxy_status['by_type'] = stats.get('by_type', {})
            return True
        else:
            log("未获取到任何节点", 'ERROR')
            return False
    except Exception as e:
        log(f"收集失败: {e}", 'ERROR')
        return False


def update_status():
    proxy_status['last_update'] = now_shanghai().strftime('%Y-%m-%d %H:%M:%S')
    proxy_status['next_update'] = (now_shanghai() + timedelta(seconds=INTERVAL_SECONDS)).strftime('%Y-%m-%d %H:%M:%S')



def get_proxy_delays(force_test: bool = False):
    """从 Clash API 获取所有节点延迟（带缓存）"""
    import requests as req
    from concurrent.futures import ThreadPoolExecutor
    
    # 检查缓存（30秒内有效）
    cache_age = time.time() - delays_cache.get('time', 0)
    if not force_test and cache_age < 30 and delays_cache.get('data'):
        return delays_cache['data']
    
    try:
        resp = req.get(f"http://127.0.0.1:{CLASH_API_PORT}/proxies/proxy", timeout=5)
        if resp.status_code != 200:
            return delays_cache.get('data', {})
        
        data = resp.json()
        all_nodes = [n for n in data.get('all', []) if n not in ['auto', 'direct', 'proxy']]
        
        if force_test:
            log(f"并发测速 {len(all_nodes)} 个节点...")
            
            def test_node(node):
                try:
                    req.get(
                        f"http://127.0.0.1:{CLASH_API_PORT}/proxies/{node}/delay",
                        params={"url": "http://www.gstatic.com/generate_204", "timeout": 3000},
                        timeout=5
                    )
                except:
                    pass
            
            with ThreadPoolExecutor(max_workers=200) as executor:
                list(executor.map(test_node, all_nodes))
            log("测速完成")
        
        # 并发获取所有节点延迟
        delays = {}
        
        def get_node_delay(node):
            try:
                node_resp = req.get(f"http://127.0.0.1:{CLASH_API_PORT}/proxies/{node}", timeout=2)
                if node_resp.status_code == 200:
                    node_data = node_resp.json()
                    delay = node_data.get('history', [{}])[-1].get('delay', 0)
                    if delay > 0:
                        return (node, delay)
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(get_node_delay, all_nodes)
            for r in results:
                if r:
                    delays[r[0]] = r[1]
        
        # 更新缓存
        delays_cache['data'] = delays
        delays_cache['time'] = time.time()
        
        return delays
    except Exception as e:
        log(f"获取延迟失败: {e}", 'ERROR')
        return delays_cache.get('data', {})


def switch_to_node(node_tag: str) -> bool:
    import requests
    try:
        resp = requests.put(
            f"http://127.0.0.1:{CLASH_API_PORT}/proxies/proxy",
            json={"name": node_tag},
            timeout=5
        )
        return resp.status_code == 204
    except:
        return False


def get_top_n_nodes(n: int = None) -> list:
    if n is None:
        n = TOP_N_NODES
    
    delays = get_proxy_delays()
    if not delays:
        return [p['tag'] for p in proxy_status.get('proxies', [])][:n]
    
    sorted_nodes = sorted(delays.items(), key=lambda x: x[1])
    return [node for node, _ in sorted_nodes[:n]]


def switch_random_node(client_ip: str = None, method: str = 'api') -> dict:
    """随机切换到 Top N 节点"""
    top_nodes = get_top_n_nodes()
    if not top_nodes:
        get_proxy_delays(force_test=True)
        top_nodes = get_top_n_nodes()
        if not top_nodes:
            return {'success': False, 'error': 'No available nodes'}
    
    selected = random.choice(top_nodes)
    
    if switch_to_node(selected):
        delays = get_proxy_delays()
        delay = delays.get(selected, 0)
        
        node_info = None
        for p in proxy_status.get('proxies_full', []):
            if p.get('tag') == selected:
                node_info = p
                break
        
        with status_lock:
            proxy_status['current_node'] = selected
            proxy_status['total_requests'] += 1
        
        return {
            'success': True,
            'node': selected,
            'delay': delay,
            'pool_size': len(top_nodes),
            'server': node_info.get('server', '') if node_info else '',
            'type': node_info.get('type', '') if node_info else ''
        }
    return {'success': False, 'error': 'Switch failed'}


def get_node_config(tag: str) -> dict:
    """获取节点的完整配置（sing-box 格式）"""
    for p in proxy_status.get('proxies_full', []):
        if p.get('tag') == tag:
            return p
    return None



# Web UI 模板 - 多标签页版本
WEB_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>代理池控制台</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .header { background: #1e293b; padding: 15px 20px; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 18px; color: #f1f5f9; }
        .header-btns { display: flex; gap: 10px; }
        .tabs { display: flex; background: #1e293b; border-bottom: 1px solid #334155; }
        .tab { padding: 12px 20px; cursor: pointer; color: #94a3b8; border-bottom: 2px solid transparent; }
        .tab:hover { color: #e2e8f0; }
        .tab.active { color: #3b82f6; border-bottom-color: #3b82f6; }
        .content { padding: 20px; max-width: 1600px; margin: 0 auto; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .card { background: #1e293b; border-radius: 8px; padding: 15px; margin-bottom: 15px; border: 1px solid #334155; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; }
        .stat { background: #0f172a; padding: 12px; border-radius: 6px; text-align: center; }
        .stat-label { color: #64748b; font-size: 11px; text-transform: uppercase; }
        .stat-value { font-size: 20px; font-weight: 700; color: #f1f5f9; margin-top: 4px; }
        .running { color: #22c55e; }
        .btn { background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
        .btn:hover { background: #2563eb; }
        .btn-green { background: #22c55e; }
        .btn-green:hover { background: #16a34a; }
        .btn-sm { padding: 5px 10px; font-size: 11px; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #64748b; font-weight: 600; position: sticky; top: 0; }
        tr:hover { background: #334155; cursor: pointer; }
        .table-wrap { max-height: 500px; overflow-y: auto; }
        .vless { color: #22d3ee; } .vmess { color: #a855f7; } .trojan { color: #f97316; }
        .shadowsocks { color: #3b82f6; } .http { color: #10b981; } .socks { color: #ec4899; }
        .log-wrap { background: #0f172a; border-radius: 6px; padding: 10px; max-height: 400px; overflow-y: auto; font-family: monospace; font-size: 11px; }
        .log-line { padding: 4px 0; border-bottom: 1px solid #1e293b; display: flex; gap: 8px; }
        .log-time { color: #64748b; min-width: 70px; }
        .log-level { min-width: 45px; font-weight: 600; }
        .log-level.INFO { color: #3b82f6; } .log-level.ERROR { color: #ef4444; } .log-level.WARN { color: #eab308; }
        .log-msg { color: #cbd5e1; word-break: break-all; }
        .req-log { display: grid; grid-template-columns: 70px 1fr 130px 150px 50px 100px; gap: 8px; padding: 6px 0; border-bottom: 1px solid #1e293b; font-size: 11px; }
        .req-log span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .exit-ip { color: #22c55e; font-weight: 600; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 100; }
        .modal.show { display: flex; justify-content: center; align-items: center; }
        .modal-content { background: #1e293b; border-radius: 8px; padding: 20px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; margin-bottom: 15px; }
        .modal-close { background: none; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; }
        pre { background: #0f172a; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #22d3ee; }
        code { font-family: 'Monaco', 'Consolas', monospace; }
        .current-node { background: #065f46; border: 1px solid #10b981; padding: 10px; border-radius: 6px; margin-top: 10px; }
        .usage-box { background: #1e3a5f; padding: 12px; border-radius: 6px; margin-top: 10px; border: 1px solid #3b82f6; font-size: 12px; }
        .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        @media (max-width: 900px) { .row2 { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 代理池控制台 <span style="font-size:12px;color:#64748b;">(sing-box)</span></h1>
        <div class="header-btns">
            <button class="btn btn-green" onclick="switchNode()">🔀 切换节点</button>
            <button class="btn" onclick="testProxy()">🧪 测试</button>
            <button class="btn" onclick="location.reload()">🔄 刷新</button>
        </div>
    </div>
    
    <div class="tabs">
        <div class="tab active" onclick="showTab('overview')">📊 概览</div>
        <div class="tab" onclick="showTab('nodes')">📋 节点</div>
        <div class="tab" onclick="showTab('top')">🏆 Top节点</div>
        <div class="tab" onclick="showTab('logs')">📝 日志</div>
        <div class="tab" onclick="showTab('api')">🔌 API</div>
    </div>
    
    <div class="content">
        <!-- 概览 -->
        <div id="tab-overview" class="tab-content active">
            <div class="card">
                <div class="grid">
                    <div class="stat"><div class="stat-label">获取节点</div><div class="stat-value" style="color:#64748b;">{{ status.proxy_count }}</div></div>
                    <div class="stat"><div class="stat-label">可用节点</div><div class="stat-value running" id="stat-available">{{ status.available_count }}</div></div>
                    <div class="stat"><div class="stat-label">Top N</div><div class="stat-value">{{ status.top_n }}</div></div>
                    <div class="stat"><div class="stat-label">请求次数</div><div class="stat-value">{{ status.total_requests }}</div></div>
                    <div class="stat"><div class="stat-label">代理端口</div><div class="stat-value">{{ status.listen_port }}</div></div>
                    <div class="stat"><div class="stat-label">状态</div><div class="stat-value {{ 'running' if status.singbox_running else '' }}">{{ '运行中' if status.singbox_running else '停止' }}</div></div>
                </div>
                {% if status.current_node %}
                <div class="current-node">
                    <span style="color:#6ee7b7;">📍 当前节点:</span> <strong>{{ status.current_node|e }}</strong>
                </div>
                {% endif %}
                <div class="usage-box">
                    <div style="color:#60a5fa;font-weight:600;margin-bottom:8px;">使用方法</div>
                    <div>1. 切换节点: <code>curl http://IP:{{ status.web_port }}/api/switch</code></div>
                    <div>2. 使用代理: <code>curl -x http://IP:{{ status.listen_port }} https://api.ipify.org</code></div>
                </div>
            </div>
            
            <div class="row2">
                <div class="card">
                    <h3 style="margin-bottom:10px;font-size:14px;">📊 请求日志</h3>
                    <div class="log-wrap" id="request-logs-overview">
                        <div style="color:#64748b;text-align:center;padding:20px;">加载中...</div>
                    </div>
                </div>
                <div class="card">
                    <h3 style="margin-bottom:10px;font-size:14px;">📝 系统日志</h3>
                    <div class="log-wrap">
                        {% for l in status.logs[-30:]|reverse %}
                        <div class="log-line">
                            <span class="log-time">{{ l.time.split(' ')[-1] }}</span>
                            <span class="log-level {{ l.level }}">{{ l.level }}</span>
                            <span class="log-msg">{{ l.msg|e }}</span>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>
        
        <!-- 节点列表 (只显示可用节点) -->
        <div id="tab-nodes" class="tab-content">
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <h3 style="font-size:14px;">✅ 可用节点 (<span id="available-count">{{ status.available_count }}</span>) - 点击查看配置</h3>
                    <button class="btn btn-sm" onclick="loadAvailableNodes()">刷新</button>
                </div>
                <div class="table-wrap" id="available-nodes-list">
                    <div style="color:#64748b;text-align:center;padding:20px;">加载中...</div>
                </div>
            </div>
        </div>
        
        <!-- Top 节点 -->
        <div id="tab-top" class="tab-content">
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <h3 style="font-size:14px;">🏆 Top {{ status.top_n }} 节点 (按延迟排序) - 点击查看配置</h3>
                    <button class="btn btn-sm" onclick="loadTopNodes()">刷新</button>
                </div>
                <div class="table-wrap" id="top-nodes-list">
                    <div style="color:#64748b;text-align:center;padding:20px;">加载中...</div>
                </div>
            </div>
        </div>
        
        <!-- 日志 -->
        <div id="tab-logs" class="tab-content">
            <div class="row2">
                <div class="card">
                    <h3 style="margin-bottom:10px;font-size:14px;">📊 请求日志</h3>
                    <div class="log-wrap" style="max-height:600px;" id="request-logs-full">
                        <div style="color:#64748b;text-align:center;padding:20px;">加载中...</div>
                    </div>
                </div>
                <div class="card">
                    <h3 style="margin-bottom:10px;font-size:14px;">📝 系统日志</h3>
                    <div class="log-wrap" style="max-height:600px;">
                        {% for l in status.logs|reverse %}
                        <div class="log-line">
                            <span class="log-time">{{ l.time.split(' ')[-1] }}</span>
                            <span class="log-level {{ l.level }}">{{ l.level }}</span>
                            <span class="log-msg">{{ l.msg|e }}</span>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>
        
        <!-- API -->
        <div id="tab-api" class="tab-content">
            <div class="card">
                <h3 style="margin-bottom:15px;font-size:14px;">🔌 API 接口</h3>
                <table>
                    <tr><td><code>GET /api/switch</code></td><td>随机切换节点</td></tr>
                    <tr><td><code>GET /api/switch/&lt;tag&gt;</code></td><td>切换到指定节点</td></tr>
                    <tr><td><code>GET /api/test</code></td><td>测试代理并返回出口IP</td></tr>
                    <tr><td><code>GET /api/nodes</code></td><td>获取所有节点及延迟</td></tr>
                    <tr><td><code>GET /api/top</code></td><td>获取Top N节点</td></tr>
                    <tr><td><code>GET /api/node/&lt;tag&gt;</code></td><td>获取节点配置(sing-box格式)</td></tr>
                    <tr><td><code>GET /api/status</code></td><td>获取系统状态</td></tr>
                    <tr><td><code>GET /api/request_logs</code></td><td>获取请求日志</td></tr>
                    <tr><td><code>GET /api/reload</code></td><td>手动触发重新加载节点</td></tr>
                    <tr><td><code>GET /api/speedtest/&lt;tag&gt;</code></td><td>测试节点下载速度</td></tr>
                    <tr><td><code>GET /api/speedtest/&lt;tag&gt;?url=xxx</code></td><td>使用自定义URL测速</td></tr>
                </table>
            </div>
            <div class="card">
                <h3 style="margin-bottom:10px;font-size:14px;">💡 Python 示例</h3>
                <pre><code>import requests

API = "http://YOUR_IP:{{ status.web_port }}"
PROXY = {"http": "http://YOUR_IP:{{ status.listen_port }}", "https": "http://YOUR_IP:{{ status.listen_port }}"}

# 方式1: 切换后请求
requests.get(f"{API}/api/switch")
r = requests.get("https://api.ipify.org", proxies=PROXY)
print(r.text)

# 方式2: 使用测试接口(自动切换+请求+记录日志)
r = requests.get(f"{API}/api/test?url=https://api.ipify.org")
print(r.json())</code></pre>
            </div>
        </div>
    </div>
    
    <!-- 节点配置弹窗 -->
    <div id="node-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modal-title">节点配置</h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <pre><code id="modal-config"></code></pre>
            <button class="btn" style="margin-top:10px;" onclick="copyConfig()">📋 复制配置</button>
        </div>
    </div>
    
    <script>
        function showTab(name) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelector(`.tab[onclick="showTab('${name}')"]`).classList.add('active');
            document.getElementById('tab-' + name).classList.add('active');
            if (name === 'top') loadTopNodes();
            if (name === 'nodes') loadAvailableNodes();
        }
        
        function switchNode() {
            fetch('/api/switch').then(r => r.json()).then(d => {
                if (d.success) {
                    alert('切换成功!\\n节点: ' + d.node + '\\n延迟: ' + d.delay + 'ms');
                    location.reload();
                } else alert('切换失败: ' + d.error);
            });
        }
        
        function testProxy() {
            fetch('/api/test').then(r => r.json()).then(d => {
                if (d.success) {
                    alert('测试成功!\\n出口IP: ' + d.exit_ip + '\\n节点: ' + d.node + '\\n延迟: ' + d.delay + 'ms');
                    loadRequestLogs();
                } else alert('测试失败: ' + d.error);
            });
        }
        
        function escapeHtml(str) {
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }
        
        function loadTopNodes() {
            document.getElementById('top-nodes-list').innerHTML = '<div style="color:#64748b;text-align:center;padding:20px;">加载中...</div>';
            fetch('/api/nodes').then(r => r.json()).then(d => {
                let html = '<table><thead><tr><th>#</th><th>类型</th><th>节点</th><th>服务器</th><th>属地</th><th>延迟</th><th>操作</th></tr></thead><tbody>';
                d.nodes.slice(0, {{ status.top_n }}).forEach((n, i) => {
                    const loc = n.location || '-';
                    const safeTag = escapeHtml(n.tag);
                    const encodedTag = encodeURIComponent(n.tag);
                    html += '<tr><td>' + (i+1) + '</td><td class="' + escapeHtml(n.type) + '">' + escapeHtml(n.type) + '</td><td title="' + safeTag + '" onclick="showNodeConfig(\\'' + encodedTag + '\\')" style="cursor:pointer;">' + safeTag.substring(0,22) + '</td><td style="color:#94a3b8;">' + escapeHtml(n.server) + '</td><td style="color:#60a5fa;">' + escapeHtml(loc) + '</td><td style="color:#fbbf24;">' + n.delay + 'ms</td><td><button class="btn btn-sm" onclick="runSpeedTest(\\'' + encodedTag + '\\')">测速</button></td></tr>';
                });
                html += '</tbody></table>';
                document.getElementById('top-nodes-list').innerHTML = html || '<div style="color:#64748b;text-align:center;padding:20px;">暂无数据</div>';
            }).catch(e => {
                document.getElementById('top-nodes-list').innerHTML = '<div style="color:#ef4444;text-align:center;padding:20px;">加载失败: ' + e.message + '</div>';
            });
        }
        
        function loadAvailableNodes() {
            document.getElementById('available-nodes-list').innerHTML = '<div style="color:#64748b;text-align:center;padding:20px;">加载中...</div>';
            fetch('/api/nodes').then(r => r.json()).then(d => {
                document.getElementById('available-count').textContent = d.total;
                let html = '<table><thead><tr><th>#</th><th>类型</th><th>节点</th><th>服务器</th><th>属地</th><th>延迟</th><th>操作</th></tr></thead><tbody>';
                d.nodes.forEach((n, i) => {
                    const loc = n.location || '-';
                    const safeTag = escapeHtml(n.tag);
                    const encodedTag = encodeURIComponent(n.tag);
                    html += '<tr><td>' + (i+1) + '</td><td class="' + escapeHtml(n.type) + '">' + escapeHtml(n.type) + '</td><td title="' + safeTag + '" onclick="showNodeConfig(\\'' + encodedTag + '\\')" style="cursor:pointer;">' + safeTag.substring(0,25) + '</td><td style="color:#94a3b8;">' + escapeHtml(n.server) + '</td><td style="color:#60a5fa;">' + escapeHtml(loc) + '</td><td style="color:#fbbf24;">' + n.delay + 'ms</td><td><button class="btn btn-sm" onclick="runSpeedTest(\\'' + encodedTag + '\\')">测速</button></td></tr>';
                });
                html += '</tbody></table>';
                document.getElementById('available-nodes-list').innerHTML = html || '<div style="color:#64748b;text-align:center;padding:20px;">暂无可用节点，请等待测速完成</div>';
            }).catch(e => {
                document.getElementById('available-nodes-list').innerHTML = '<div style="color:#ef4444;text-align:center;padding:20px;">加载失败: ' + e.message + '</div>';
            });
        }
        
        function loadRequestLogs() {
            fetch('/api/request_logs').then(r => r.json()).then(d => {
                let html = '';
                if (d.logs && d.logs.length > 0) {
                    d.logs.slice().reverse().forEach(l => {
                        const time = (l.time || '').split(' ')[1] || '-';
                        const target = (l.target || '-').substring(0, 30);
                        const exitIp = l.exit_ip || '-';
                        const node = (l.node || '-').substring(0, 20);
                        const delay = l.delay || 0;
                        const method = l.method || '-';
                        html += '<div class="req-log"><span style="color:#64748b;">' + escapeHtml(time) + '</span><span title="' + escapeHtml(l.target || '') + '">' + escapeHtml(target) + '</span><span class="exit-ip">' + escapeHtml(exitIp) + '</span><span style="color:#22d3ee;">' + escapeHtml(node) + '</span><span style="color:#fbbf24;">' + delay + 'ms</span><span style="color:#a78bfa;">' + escapeHtml(method) + '</span></div>';
                    });
                }
                document.getElementById('request-logs-overview').innerHTML = html || '<div style="color:#64748b;text-align:center;padding:20px;">暂无代理请求</div>';
                document.getElementById('request-logs-full').innerHTML = html || '<div style="color:#64748b;text-align:center;padding:20px;">暂无代理请求</div>';
            }).catch(e => {
                console.error('加载日志失败:', e);
            });
        }
        
        function showNodeConfig(encodedTag) {
            const tag = decodeURIComponent(encodedTag);
            fetch('/api/node/' + encodedTag).then(r => r.json()).then(d => {
                if (d.config) {
                    document.getElementById('modal-title').textContent = tag;
                    document.getElementById('modal-config').textContent = JSON.stringify(d.config, null, 2);
                    document.getElementById('node-modal').classList.add('show');
                }
            });
        }
        
        function closeModal() { document.getElementById('node-modal').classList.remove('show'); }
        function copyConfig() {
            navigator.clipboard.writeText(document.getElementById('modal-config').textContent);
            alert('已复制到剪贴板');
        }
        
        function runSpeedTest(encodedTag) {
            const tag = decodeURIComponent(encodedTag);
            const testUrl = prompt('测试文件URL (留空使用默认1MB文件):', '');
            const url = testUrl ? `/api/speedtest/${encodedTag}?url=${encodeURIComponent(testUrl)}` : `/api/speedtest/${encodedTag}`;
            
            // 显示测试中
            document.getElementById('modal-title').textContent = '速度测试: ' + tag;
            document.getElementById('modal-config').textContent = '测试中，请稍候...\\n\\n下载测试文件并计算速度...';
            document.getElementById('node-modal').classList.add('show');
            
            fetch(url).then(r => r.json()).then(d => {
                let result = '';
                if (d.success) {
                    result = '节点: ' + d.node + '\\n\\n✅ 测试成功\\n\\n📊 测试结果:\\n   延迟: ' + d.latency + ' ms\\n   下载速度: ' + d.download_speed + ' MB/s\\n   文件大小: ' + (d.file_size / 1024 / 1024).toFixed(2) + ' MB\\n   耗时: ' + d.time_taken + ' 秒\\n\\n📁 测试文件: ' + d.test_url;
                } else {
                    result = '节点: ' + d.node + '\\n\\n❌ 测试失败\\n\\n错误: ' + (d.error || '未知错误');
                }
                document.getElementById('modal-config').textContent = result;
            }).catch(e => {
                document.getElementById('modal-config').textContent = '测试失败: ' + e.message;
            });
        }
        
        // 初始化
        loadTopNodes();
        loadAvailableNodes();
        loadRequestLogs();
        setInterval(loadRequestLogs, 10000);
    </script>
</body>
</html>'''



def start_web_server():
    if not FLASK_AVAILABLE:
        log("Flask 未安装，Web UI 不可用", 'WARN')
        return
    
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        with status_lock:
            status_copy = {
                'proxy_count': proxy_status.get('proxy_count', 0),
                'available_count': proxy_status.get('available_count', 0),
                'singbox_running': proxy_status.get('singbox_running', False),
                'listen_port': proxy_status.get('listen_port'),
                'total_requests': proxy_status.get('total_requests', 0),
                'current_node': proxy_status.get('current_node'),
                'top_n': TOP_N_NODES,
                'web_port': WEB_PORT,
                'logs': list(proxy_status.get('logs', []))[-100:],
                'proxies': list(proxy_status.get('proxies', []))[:200],
            }
        return render_template_string(WEB_TEMPLATE, status=status_copy)
    
    @app.route('/api/status')
    def api_status():
        with status_lock:
            return jsonify({
                'proxy_count': proxy_status.get('proxy_count', 0),
                'available_count': proxy_status.get('available_count', 0),
                'singbox_running': proxy_status.get('singbox_running', False),
                'listen_port': proxy_status.get('listen_port'),
                'total_requests': proxy_status.get('total_requests', 0),
                'current_node': proxy_status.get('current_node'),
                'speedtest_done': proxy_status.get('speedtest_done', False),
                'top_n': TOP_N_NODES,
            })
    
    @app.route('/api/switch', methods=['GET', 'POST'])
    def api_switch():
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        result = switch_random_node(client_ip, 'switch')
        return jsonify(result)
    
    @app.route('/api/switch/<node_tag>', methods=['GET', 'POST'])
    def api_switch_to(node_tag):
        if switch_to_node(node_tag):
            with status_lock:
                proxy_status['current_node'] = node_tag
            return jsonify({'success': True, 'node': node_tag})
        return jsonify({'success': False, 'error': 'Switch failed'})
    
    @app.route('/api/test')
    def api_test():
        import requests as req
        import urllib3
        urllib3.disable_warnings()
        
        target_url = request.args.get('url', 'https://api.ipify.org')
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        switch_result = switch_random_node(client_ip, 'test')
        if not switch_result.get('success'):
            return jsonify({'success': False, 'error': 'Switch failed'})
        
        try:
            proxy_url = f"http://127.0.0.1:{LISTEN_PORT}"
            resp = req.get(target_url, proxies={'http': proxy_url, 'https': proxy_url}, timeout=10, verify=False)
            exit_ip = resp.text.strip()[:50]
            
            log_request(target_url, exit_ip, switch_result.get('node', ''), switch_result.get('delay', 0), client_ip, 'test')
            
            return jsonify({
                'success': True,
                'target': target_url,
                'exit_ip': exit_ip,
                'node': switch_result.get('node'),
                'delay': switch_result.get('delay'),
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    @app.route('/api/nodes')
    def api_nodes():
        delays = get_proxy_delays()
        sorted_nodes = sorted(delays.items(), key=lambda x: x[1])
        with status_lock:
            proxy_status['available_count'] = len(sorted_nodes)
            proxies_full = proxy_status.get('proxies_full', [])
        
        # 构建节点信息（包含 server 和属地）
        nodes_info = []
        servers_to_query = []
        
        for tag, delay in sorted_nodes:
            node = {'tag': tag, 'delay': delay, 'server': '', 'type': '', 'location': ''}
            for p in proxies_full:
                if p.get('tag') == tag:
                    server = p.get('server', '')
                    node['server'] = server
                    node['type'] = p.get('type', '')
                    node['location'] = ip_location_cache.get(server, '')
                    if server and server not in ip_location_cache:
                        servers_to_query.append(server)
                    break
            nodes_info.append(node)
        
        # 后台异步查询属地（不阻塞响应）
        if servers_to_query:
            Thread(target=batch_get_ip_locations, args=(servers_to_query[:100], False), daemon=True).start()
        
        return jsonify({
            'total': len(sorted_nodes),
            'top_n': TOP_N_NODES,
            'nodes': nodes_info
        })
    
    @app.route('/api/top')
    def api_top():
        return jsonify({'top_n': TOP_N_NODES, 'nodes': get_top_n_nodes()})
    
    @app.route('/api/node/<path:tag>')
    def api_node_config(tag):
        config = get_node_config(tag)
        if config:
            return jsonify({'success': True, 'config': config})
        return jsonify({'success': False, 'error': 'Node not found'})
    
    @app.route('/api/request_logs')
    def api_request_logs():
        with status_lock:
            return jsonify({'logs': list(proxy_status.get('request_logs', []))})
    
    @app.route('/api/reload')
    def api_reload():
        """手动触发重新加载节点"""
        def do_reload():
            log("手动触发节点重载...")
            if collect_nodes():
                log("节点重载完成，需要重启 sing-box 生效")
        Thread(target=do_reload, daemon=True).start()
        return jsonify({'success': True, 'message': '后台重载中，请稍后刷新'})
    
    @app.route('/api/speedtest/<path:node_tag>')
    def api_speedtest(node_tag):
        """测试指定节点的下载速度"""
        test_url = request.args.get('url', None)
        result = test_node_speed(node_tag, test_url)
        if result['success']:
            log(f"速度测试: {node_tag} - {result['download_speed']} MB/s, {result['latency']}ms")
        return jsonify(result)
    
    @app.route('/api/speedtest_cache')
    def api_speedtest_cache():
        """获取速度测试缓存"""
        return jsonify(speed_test_cache)
    
    log(f"Web UI: http://0.0.0.0:{WEB_PORT}")
    app.run(host='0.0.0.0', port=WEB_PORT, threaded=True, use_reloader=False)


# ==================== 后台任务 ====================
class BackgroundTasks:
    """后台任务管理"""
    
    def __init__(self, singbox_holder: list):
        self.singbox_holder = singbox_holder
    
    def start_all(self) -> None:
        """启动所有后台任务"""
        Thread(target=self._background_speedtest, daemon=True).start()
        
        if CFG.auto_switch_interval > 0:
            Thread(target=self._auto_switch, daemon=True).start()
        
        Thread(target=self._scheduled_update, daemon=True).start()
    
    def _background_speedtest(self) -> None:
        """后台测速"""
        time.sleep(5)
        log("后台测速...")
        get_proxy_delays(force_test=True)
        delays = get_proxy_delays()
        with status_lock:
            proxy_status['speedtest_done'] = True
            proxy_status['available_count'] = len(delays)
        log(f"测速完成，可用节点: {len(delays)} 个")
    
    def _auto_switch(self) -> None:
        """自动切换节点"""
        time.sleep(30)
        log(f"启动自动切换，间隔: {CFG.auto_switch_interval}秒")
        while True:
            time.sleep(CFG.auto_switch_interval)
            result = switch_random_node("auto", "auto")
            if result.get('success'):
                log(f"自动切换: {result.get('node')} ({result.get('delay')}ms)")
    
    def _scheduled_update(self) -> None:
        """定时更新 (00:00, 12:00)"""
        while True:
            now = now_shanghai()
            if now.hour < 12:
                next_run = now.replace(hour=12, minute=0, second=0, microsecond=0)
            else:
                next_run = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            
            wait_seconds = (next_run - now).total_seconds()
            log(f"下次定时更新: {next_run.strftime('%Y-%m-%d %H:%M')}")
            time.sleep(wait_seconds)
            
            self._do_update(force_online=True)
    
    def _do_update(self, force_online: bool = False) -> None:
        """执行节点更新"""
        if force_online:
            log("执行定时更新（包含在线代理源）...")
            os.environ['FORCE_ONLINE_SOURCES'] = 'true'
        else:
            log("开始更新...")
        
        if collect_nodes():
            kill_singbox(self.singbox_holder[0])
            self.singbox_holder[0] = run_singbox()
            update_status()
            time.sleep(5)
            get_proxy_delays(force_test=True)
            log("更新完成")


def init_service() -> bool:
    """初始化服务"""
    log("=" * 50)
    log("代理池服务启动 (sing-box)")
    log(f"监听端口: {CFG.listen_port}, Top N: {CFG.top_n_nodes}")
    log(f"更新间隔: {CFG.interval_seconds}秒")
    log("=" * 50)
    
    singbox_path = Path(CFG.singbox_binary)
    if not singbox_path.exists():
        log(f"sing-box 不存在: {singbox_path}", 'ERROR')
        return False
    
    log("执行首次节点收集...")
    if not collect_nodes():
        if not CFG.config_path.exists():
            log("无可用配置，退出", 'ERROR')
            return False
    
    update_status()
    return True


def main():
    if not init_service():
        sys.exit(1)
    
    if CFG.enable_web_ui and FLASK_AVAILABLE:
        Thread(target=start_web_server, daemon=True).start()
    
    singbox_holder = [None]
    
    def cleanup(signum, frame):
        log("收到终止信号...")
        kill_singbox(singbox_holder[0])
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    
    try:
        singbox_holder[0] = run_singbox()
        if not singbox_holder[0]:
            sys.exit(1)
        
        log("代理服务已就绪")
        
        # 启动后台任务
        tasks = BackgroundTasks(singbox_holder)
        tasks.start_all()
        
        # 主循环
        while True:
            log(f"等待 {CFG.interval_seconds}秒 后更新...")
            time.sleep(CFG.interval_seconds)
            tasks._do_update()
    
    except KeyboardInterrupt:
        kill_singbox(singbox_holder[0])
        sys.exit(0)


if __name__ == "__main__":
    main()
