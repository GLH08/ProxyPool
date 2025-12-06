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
import re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from threading import Thread, Lock, Event
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# 上海时区 (UTC+8)
SHANGHAI_TZ = timezone(timedelta(hours=8))


def now_shanghai() -> datetime:
    """获取上海时区当前时间"""
    return datetime.now(SHANGHAI_TZ)


# 配置日志
class ShanghaiFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = now_shanghai()
        if datefmt:
            return ct.strftime(datefmt)
        return ct.strftime('%Y-%m-%d %H:%M:%S')


logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
for handler in logging.root.handlers:
    handler.setFormatter(ShanghaiFormatter('[%(asctime)s] [%(levelname)s] %(message)s'))

logger = logging.getLogger(__name__)

try:
    from flask import Flask, jsonify, render_template, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


# ==================== 配置类 ====================
@dataclass
class Config:
    """应用配置"""
    # 路径
    singbox_binary: str = os.environ.get('SINGBOX_BINARY', '/usr/local/bin/sing-box')
    config_path: Path = field(default_factory=lambda: Path('config/sing-box.json'))
    template_dir: Path = field(default_factory=lambda: Path('templates'))
    
    # 端口
    listen_port: int = int(os.environ.get('LISTEN_PORT', '10710'))
    web_port: int = int(os.environ.get('WEB_PORT', '8080'))
    clash_api_port: int = int(os.environ.get('CLASH_API_PORT', '9090'))
    
    # 功能开关
    enable_web_ui: bool = os.environ.get('ENABLE_WEB_UI', 'true').lower() == 'true'
    
    # 节点相关
    top_n_nodes: int = int(os.environ.get('TOP_N_NODES', '50'))
    max_display_proxies: int = 500
    
    # 时间间隔（秒）
    interval_seconds: int = int(os.environ.get('INTERVAL_SECONDS', '1800'))
    auto_switch_interval: int = int(os.environ.get('AUTO_SWITCH_INTERVAL', '0'))
    
    # 日志
    max_logs: int = 500
    max_request_logs: int = 200
    
    # 并发
    speedtest_workers: int = 200
    delay_fetch_workers: int = 50
    ip_location_workers: int = 20
    
    # 超时（秒）
    api_timeout: int = 5
    proxy_test_timeout: int = 10
    speedtest_timeout: int = 30
    
    # 速度测试
    default_speedtest_url: str = "http://speedtest.tele2.net/5MB.zip"
    max_speedtest_size: int = 10 * 1024 * 1024  # 10MB
    
    # 缓存过期时间（秒）
    delay_cache_ttl: int = 30
    
    # sing-box 重启
    singbox_restart_delay: int = 5
    singbox_max_restarts: int = 3


# 全局配置实例
CFG = Config()


# ==================== 状态管理 ====================
class ProxyStatus:
    """代理池状态（线程安全）"""
    
    def __init__(self):
        self._lock = Lock()
        self._data = {
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
    
    def get(self, key: str, default=None):
        with self._lock:
            return self._data.get(key, default)
    
    def set(self, key: str, value):
        with self._lock:
            self._data[key] = value
    
    def update(self, **kwargs):
        with self._lock:
            self._data.update(kwargs)
    
    def get_snapshot(self, keys: List[str] = None) -> dict:
        """获取状态快照"""
        with self._lock:
            if keys:
                return {k: self._data.get(k) for k in keys}
            return dict(self._data)
    
    def append_log(self, log_entry: dict):
        with self._lock:
            self._data['logs'].append(log_entry)
    
    def append_request_log(self, log_entry: dict):
        with self._lock:
            self._data['request_logs'].append(log_entry)
    
    def increment_requests(self):
        with self._lock:
            self._data['total_requests'] += 1


# 全局状态实例
proxy_status = ProxyStatus()

# 缓存
ip_location_cache: Dict[str, str] = {}
speed_test_cache: Dict[str, Dict] = {}
delays_cache: Dict[str, Any] = {'data': {}, 'time': 0}
delays_cache_lock = Lock()


# ==================== 日志函数 ====================
def log(message: str, level: str = 'INFO'):
    """记录日志"""
    timestamp = now_shanghai().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] [{level}] {message}"
    print(log_line, flush=True)
    proxy_status.append_log({'time': timestamp, 'level': level, 'msg': message})


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
    proxy_status.append_request_log(log_entry)
    print(f"[{timestamp}] [REQUEST] {method} | {target} | {exit_ip} | {node} | {delay}ms | {client}", flush=True)


# ==================== IP 属地查询 ====================
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
    except Exception:
        pass
    
    ip_location_cache[ip] = ''
    return ''


def batch_get_ip_locations(ips: List[str], wait: bool = False) -> None:
    """批量查询 IP 属地"""
    new_ips = [ip for ip in ips if ip and ip not in ip_location_cache]
    if not new_ips:
        return
    
    new_ips = new_ips[:100]
    
    with ThreadPoolExecutor(max_workers=CFG.ip_location_workers) as executor:
        futures = [executor.submit(get_ip_location, ip) for ip in new_ips]
        if wait:
            for f in as_completed(futures, timeout=10):
                try:
                    f.result()
                except Exception:
                    pass


# ==================== sing-box 配置生成 ====================
def generate_singbox_config(outbounds: list) -> dict:
    """生成 sing-box 配置"""
    tags = [ob['tag'] for ob in outbounds]
    
    return {
        "log": {
            "level": "info",
            "timestamp": True,
            "output": ""
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"0.0.0.0:{CFG.clash_api_port}",
                "default_mode": "rule"
            }
        },
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "0.0.0.0",
            "listen_port": CFG.listen_port,
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


def write_config(outbounds: list) -> None:
    """写入配置文件"""
    config = generate_singbox_config(outbounds)
    CFG.config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(CFG.config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    log(f"配置已写入: {CFG.config_path}")


# ==================== sing-box 进程管理 ====================
class SingboxManager:
    """sing-box 进程管理器"""
    
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.restart_count = 0
        self._stop_event = Event()
        self._monitor_thread: Optional[Thread] = None
    
    def start(self) -> bool:
        """启动 sing-box"""
        try:
            log("启动 sing-box...")
            self.process = subprocess.Popen(
                [CFG.singbox_binary, "run", "-c", str(CFG.config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            proxy_status.set('singbox_running', True)
            
            # 启动日志读取线程
            Thread(target=self._read_logs, daemon=True).start()
            
            # 启动监控线程
            self._stop_event.clear()
            self._monitor_thread = Thread(target=self._monitor, daemon=True)
            self._monitor_thread.start()
            
            return True
        except Exception as e:
            log(f"启动 sing-box 失败: {e}", 'ERROR')
            proxy_status.set('singbox_running', False)
            return False
    
    def stop(self) -> None:
        """停止 sing-box"""
        self._stop_event.set()
        if self.process:
            try:
                log("停止 sing-box...")
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception:
                pass
            self.process = None
        proxy_status.set('singbox_running', False)
    
    def restart(self) -> bool:
        """重启 sing-box"""
        self.stop()
        time.sleep(CFG.singbox_restart_delay)
        return self.start()
    
    def _read_logs(self) -> None:
        """读取 sing-box 日志"""
        if not self.process or not self.process.stdout:
            return
        
        try:
            for line in iter(self.process.stdout.readline, ''):
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                
                # 记录错误日志
                if 'error' in line.lower() or 'fatal' in line.lower():
                    log(f"[sing-box] {line[:200]}", 'ERROR')
                
                # 解析连接日志
                if 'connection' in line.lower() and ('inbound' in line.lower() or 'outbound' in line.lower()):
                    print(f"[PROXY] {line}", flush=True)
                    match = re.search(r'connection.*?to\s+([^\s:]+):?(\d+)?', line, re.IGNORECASE)
                    if match:
                        target = match.group(1)
                        port = match.group(2) or '443'
                        timestamp = now_shanghai().strftime('%Y-%m-%d %H:%M:%S')
                        proxy_status.append_request_log({
                            'time': timestamp,
                            'target': f"{target}:{port}",
                            'exit_ip': '-',
                            'node': proxy_status.get('current_node', 'auto'),
                            'delay': 0,
                            'client': 'proxy',
                            'method': 'CONNECT'
                        })
        except Exception:
            pass
    
    def _monitor(self) -> None:
        """监控 sing-box 进程，崩溃时自动重启"""
        while not self._stop_event.is_set():
            if self.process and self.process.poll() is not None:
                # 进程已退出
                exit_code = self.process.returncode
                log(f"sing-box 进程退出，退出码: {exit_code}", 'WARN')
                proxy_status.set('singbox_running', False)
                
                if self.restart_count < CFG.singbox_max_restarts:
                    self.restart_count += 1
                    log(f"尝试重启 sing-box ({self.restart_count}/{CFG.singbox_max_restarts})...")
                    time.sleep(CFG.singbox_restart_delay)
                    if self.start():
                        log("sing-box 重启成功")
                        self.restart_count = 0
                    else:
                        log("sing-box 重启失败", 'ERROR')
                else:
                    log(f"sing-box 重启次数超过限制 ({CFG.singbox_max_restarts})，停止重启", 'ERROR')
                    break
            
            time.sleep(5)


# 全局 sing-box 管理器
singbox_manager = SingboxManager()


# ==================== 节点管理 ====================
def collect_nodes() -> bool:
    """收集订阅节点"""
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
            proxy_status.update(
                proxy_count=len(outbounds),
                proxies=[
                    {'type': ob.get('type', 'unknown'), 'tag': ob.get('tag', ''),
                     'server': ob.get('server', ''), 'port': ob.get('server_port', 0)}
                    for ob in outbounds[:CFG.max_display_proxies]
                ],
                proxies_full=outbounds,
                by_type=stats.get('by_type', {})
            )
            return True
        else:
            log("未获取到任何节点", 'ERROR')
            return False
    except Exception as e:
        log(f"收集失败: {e}", 'ERROR')
        return False


def update_status() -> None:
    """更新状态时间"""
    proxy_status.update(
        last_update=now_shanghai().strftime('%Y-%m-%d %H:%M:%S'),
        next_update=(now_shanghai() + timedelta(seconds=CFG.interval_seconds)).strftime('%Y-%m-%d %H:%M:%S')
    )


# ==================== 延迟测试 ====================
def get_proxy_delays(force_test: bool = False) -> Dict[str, int]:
    """从 Clash API 获取所有节点延迟（带缓存）"""
    import requests as req
    
    with delays_cache_lock:
        cache_age = time.time() - delays_cache.get('time', 0)
        if not force_test and cache_age < CFG.delay_cache_ttl and delays_cache.get('data'):
            return delays_cache['data']
    
    try:
        resp = req.get(f"http://127.0.0.1:{CFG.clash_api_port}/proxies/proxy", timeout=5)
        if resp.status_code != 200:
            with delays_cache_lock:
                return delays_cache.get('data', {})
        
        data = resp.json()
        all_nodes = [n for n in data.get('all', []) if n not in ['auto', 'direct', 'proxy']]
        
        if force_test:
            log(f"并发测速 {len(all_nodes)} 个节点...")
            
            def test_node(node):
                try:
                    req.get(
                        f"http://127.0.0.1:{CFG.clash_api_port}/proxies/{node}/delay",
                        params={"url": "http://www.gstatic.com/generate_204", "timeout": 3000},
                        timeout=5
                    )
                except Exception:
                    pass
            
            with ThreadPoolExecutor(max_workers=CFG.speedtest_workers) as executor:
                list(executor.map(test_node, all_nodes))
            log("测速完成")
        
        # 并发获取所有节点延迟
        delays = {}
        
        def get_node_delay(node):
            try:
                node_resp = req.get(f"http://127.0.0.1:{CFG.clash_api_port}/proxies/{node}", timeout=2)
                if node_resp.status_code == 200:
                    node_data = node_resp.json()
                    delay = node_data.get('history', [{}])[-1].get('delay', 0)
                    if delay > 0:
                        return (node, delay)
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=CFG.delay_fetch_workers) as executor:
            results = executor.map(get_node_delay, all_nodes)
            for r in results:
                if r:
                    delays[r[0]] = r[1]
        
        # 更新缓存
        with delays_cache_lock:
            delays_cache['data'] = delays
            delays_cache['time'] = time.time()
        
        return delays
    except Exception as e:
        log(f"获取延迟失败: {e}", 'ERROR')
        with delays_cache_lock:
            return delays_cache.get('data', {})


def switch_to_node(node_tag: str) -> bool:
    """切换到指定节点"""
    import requests
    try:
        resp = requests.put(
            f"http://127.0.0.1:{CFG.clash_api_port}/proxies/proxy",
            json={"name": node_tag},
            timeout=5
        )
        return resp.status_code == 204
    except Exception:
        return False


def get_top_n_nodes(n: int = None) -> List[str]:
    """获取 Top N 低延迟节点"""
    if n is None:
        n = CFG.top_n_nodes
    
    delays = get_proxy_delays()
    if not delays:
        proxies = proxy_status.get('proxies', [])
        return [p['tag'] for p in proxies][:n]
    
    sorted_nodes = sorted(delays.items(), key=lambda x: x[1])
    return [node for node, _ in sorted_nodes[:n]]


def switch_random_node(client_ip: str = None, method: str = 'api', exclude_current: bool = True) -> dict:
    """随机切换到 Top N 节点（可排除当前节点）"""
    top_nodes = get_top_n_nodes()
    if not top_nodes:
        get_proxy_delays(force_test=True)
        top_nodes = get_top_n_nodes()
        if not top_nodes:
            return {'success': False, 'error': 'No available nodes'}
    
    # 排除当前节点（如果有多个可选）
    current = proxy_status.get('current_node')
    if exclude_current and current and len(top_nodes) > 1:
        top_nodes = [n for n in top_nodes if n != current]
    
    selected = random.choice(top_nodes)
    
    if switch_to_node(selected):
        delays = get_proxy_delays()
        delay = delays.get(selected, 0)
        
        node_info = None
        for p in proxy_status.get('proxies_full', []):
            if p.get('tag') == selected:
                node_info = p
                break
        
        proxy_status.set('current_node', selected)
        proxy_status.increment_requests()
        
        return {
            'success': True,
            'node': selected,
            'delay': delay,
            'pool_size': len(top_nodes),
            'server': node_info.get('server', '') if node_info else '',
            'type': node_info.get('type', '') if node_info else ''
        }
    return {'success': False, 'error': 'Switch failed'}


def get_node_config(tag: str) -> Optional[dict]:
    """获取节点的完整配置"""
    for p in proxy_status.get('proxies_full', []):
        if p.get('tag') == tag:
            return p
    return None


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
        'download_speed': 0,
        'latency': 0,
        'test_url': test_url,
        'file_size': 0,
        'time_taken': 0,
    }
    
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


# ==================== Web 服务 ====================
def start_web_server() -> None:
    """启动 Web 服务"""
    if not FLASK_AVAILABLE:
        log("Flask 未安装，Web UI 不可用", 'WARN')
        return
    
    import logging as flask_logging
    flask_logging.getLogger('werkzeug').setLevel(flask_logging.ERROR)
    
    app = Flask(__name__, template_folder=str(CFG.template_dir))
    
    @app.route('/')
    def index():
        status_copy = {
            'proxy_count': proxy_status.get('proxy_count', 0),
            'available_count': proxy_status.get('available_count', 0),
            'singbox_running': proxy_status.get('singbox_running', False),
            'listen_port': proxy_status.get('listen_port'),
            'total_requests': proxy_status.get('total_requests', 0),
            'current_node': proxy_status.get('current_node'),
            'top_n': CFG.top_n_nodes,
            'web_port': CFG.web_port,
            'logs': list(proxy_status.get('logs', []))[-100:],
            'proxies': list(proxy_status.get('proxies', []))[:200],
        }
        return render_template('index.html', status=status_copy)
    
    @app.route('/api/status')
    def api_status():
        return jsonify({
            'proxy_count': proxy_status.get('proxy_count', 0),
            'available_count': proxy_status.get('available_count', 0),
            'singbox_running': proxy_status.get('singbox_running', False),
            'listen_port': proxy_status.get('listen_port'),
            'total_requests': proxy_status.get('total_requests', 0),
            'current_node': proxy_status.get('current_node'),
            'speedtest_done': proxy_status.get('speedtest_done', False),
            'top_n': CFG.top_n_nodes,
        })
    
    @app.route('/api/switch', methods=['GET', 'POST'])
    def api_switch():
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        result = switch_random_node(client_ip, 'switch')
        return jsonify(result)
    
    @app.route('/api/switch/<node_tag>', methods=['GET', 'POST'])
    def api_switch_to(node_tag):
        if switch_to_node(node_tag):
            proxy_status.set('current_node', node_tag)
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
            proxy_url = f"http://127.0.0.1:{CFG.listen_port}"
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
        proxy_status.set('available_count', len(sorted_nodes))
        proxies_full = proxy_status.get('proxies_full', [])
        
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
        
        if servers_to_query:
            Thread(target=batch_get_ip_locations, args=(servers_to_query[:100], False), daemon=True).start()
        
        return jsonify({
            'total': len(sorted_nodes),
            'top_n': CFG.top_n_nodes,
            'nodes': nodes_info
        })
    
    @app.route('/api/top')
    def api_top():
        return jsonify({'top_n': CFG.top_n_nodes, 'nodes': get_top_n_nodes()})
    
    @app.route('/api/node/<path:tag>')
    def api_node_config(tag):
        config = get_node_config(tag)
        if config:
            return jsonify({'success': True, 'config': config})
        return jsonify({'success': False, 'error': 'Node not found'})
    
    @app.route('/api/request_logs')
    def api_request_logs():
        return jsonify({'logs': list(proxy_status.get('request_logs', []))})
    
    @app.route('/api/reload')
    def api_reload():
        def do_reload():
            log("手动触发节点重载...")
            if collect_nodes():
                log("节点重载完成，需要重启 sing-box 生效")
        Thread(target=do_reload, daemon=True).start()
        return jsonify({'success': True, 'message': '后台重载中，请稍后刷新'})
    
    @app.route('/api/speedtest/<path:node_tag>')
    def api_speedtest(node_tag):
        test_url = request.args.get('url', None)
        result = test_node_speed(node_tag, test_url)
        if result['success']:
            log(f"速度测试: {node_tag} - {result['download_speed']} MB/s, {result['latency']}ms")
        return jsonify(result)
    
    @app.route('/api/speedtest_cache')
    def api_speedtest_cache():
        return jsonify(speed_test_cache)
    
    @app.route('/api/health')
    def api_health():
        """健康检查 - 真正测试代理是否可用"""
        import requests as req
        import urllib3
        urllib3.disable_warnings()
        
        health = {
            'healthy': False,
            'singbox_running': proxy_status.get('singbox_running', False),
            'available_nodes': proxy_status.get('available_count', 0),
            'proxy_test': None
        }
        
        if not health['singbox_running']:
            return jsonify(health), 503
        
        # 测试代理是否真正可用
        try:
            proxy_url = f"http://127.0.0.1:{CFG.listen_port}"
            resp = req.get(
                "http://www.gstatic.com/generate_204",
                proxies={'http': proxy_url, 'https': proxy_url},
                timeout=5,
                verify=False
            )
            health['proxy_test'] = resp.status_code == 204
            health['healthy'] = health['proxy_test'] and health['available_nodes'] > 0
        except Exception as e:
            health['proxy_test'] = False
            health['error'] = str(e)[:100]
        
        status_code = 200 if health['healthy'] else 503
        return jsonify(health), status_code
    
    @app.route('/api/restart_singbox', methods=['POST'])
    def api_restart_singbox():
        """手动重启 sing-box"""
        def do_restart():
            log("手动触发 sing-box 重启...")
            singbox_manager.restart()
        Thread(target=do_restart, daemon=True).start()
        return jsonify({'success': True, 'message': '正在重启 sing-box'})
    
    log(f"Web UI: http://0.0.0.0:{CFG.web_port}")
    app.run(host='0.0.0.0', port=CFG.web_port, threaded=True, use_reloader=False)


# ==================== 后台任务 ====================
class BackgroundTasks:
    """后台任务管理"""
    
    def __init__(self):
        self._stop_event = Event()
        self._force_online = Event()
    
    def start_all(self) -> None:
        """启动所有后台任务"""
        Thread(target=self._background_speedtest, daemon=True).start()
        
        if CFG.auto_switch_interval > 0:
            Thread(target=self._auto_switch, daemon=True).start()
        
        Thread(target=self._scheduled_update, daemon=True).start()
    
    def stop(self) -> None:
        """停止所有任务"""
        self._stop_event.set()
    
    def _background_speedtest(self) -> None:
        """后台测速"""
        time.sleep(5)
        log("后台测速...")
        get_proxy_delays(force_test=True)
        delays = get_proxy_delays()
        proxy_status.update(
            speedtest_done=True,
            available_count=len(delays)
        )
        log(f"测速完成，可用节点: {len(delays)} 个")
    
    def _auto_switch(self) -> None:
        """自动切换节点"""
        time.sleep(30)
        log(f"启动自动切换，间隔: {CFG.auto_switch_interval}秒")
        while not self._stop_event.is_set():
            time.sleep(CFG.auto_switch_interval)
            if self._stop_event.is_set():
                break
            result = switch_random_node("auto", "auto")
            if result.get('success'):
                log(f"自动切换: {result.get('node')} ({result.get('delay')}ms)")
    
    def _scheduled_update(self) -> None:
        """定时更新 (00:00, 12:00)"""
        while not self._stop_event.is_set():
            now = now_shanghai()
            if now.hour < 12:
                next_run = now.replace(hour=12, minute=0, second=0, microsecond=0)
            else:
                next_run = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            
            wait_seconds = (next_run - now).total_seconds()
            log(f"下次定时更新: {next_run.strftime('%Y-%m-%d %H:%M')}")
            
            # 分段等待，以便响应停止信号
            while wait_seconds > 0 and not self._stop_event.is_set():
                sleep_time = min(wait_seconds, 60)
                time.sleep(sleep_time)
                wait_seconds -= sleep_time
            
            if self._stop_event.is_set():
                break
            
            self._do_update(force_online=True)
    
    def _do_update(self, force_online: bool = False) -> None:
        """执行节点更新"""
        if force_online:
            log("执行定时更新（包含在线代理源）...")
            os.environ['FORCE_ONLINE_SOURCES'] = 'true'
        else:
            log("开始更新...")
        
        try:
            if collect_nodes():
                singbox_manager.restart()
                update_status()
                time.sleep(5)
                get_proxy_delays(force_test=True)
                log("更新完成")
        finally:
            # 清理环境变量
            os.environ.pop('FORCE_ONLINE_SOURCES', None)


# ==================== 主程序 ====================
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
    
    # 启动 Web 服务
    if CFG.enable_web_ui and FLASK_AVAILABLE:
        Thread(target=start_web_server, daemon=True).start()
    
    # 信号处理
    def cleanup(signum, frame):
        log("收到终止信号...")
        tasks.stop()
        singbox_manager.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    
    try:
        # 启动 sing-box
        if not singbox_manager.start():
            sys.exit(1)
        
        log("代理服务已就绪")
        
        # 启动后台任务
        tasks = BackgroundTasks()
        tasks.start_all()
        
        # 主循环
        while True:
            log(f"等待 {CFG.interval_seconds}秒 后更新...")
            time.sleep(CFG.interval_seconds)
            tasks._do_update()
    
    except KeyboardInterrupt:
        singbox_manager.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
