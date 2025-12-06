#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
订阅解析器 - 支持多种协议，输出 sing-box outbound 格式
支持: ss, vmess, vless, trojan, hysteria2, hy2
"""
import base64
import json
import re
import os
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

import yaml

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger(__name__)


# ==================== 配置 ====================
@dataclass
class ParserConfig:
    """解析器配置"""
    max_nodes: int = int(os.environ.get('MAX_NODES', '500'))
    subscriptions_file: str = os.environ.get('SUBSCRIPTIONS_FILE', 'subscriptions.txt')
    http_proxies_file: str = os.environ.get('HTTP_PROXIES_FILE', 'http_alive.txt')
    https_proxies_file: str = os.environ.get('HTTPS_PROXIES_FILE', 'https_alive.txt')
    proxy_sources_file: str = os.environ.get('PROXY_SOURCES_FILE', 'proxy_sources.txt')
    enable_online_sources: bool = os.environ.get('ENABLE_ONLINE_SOURCES', 'false').lower() == 'true'
    scheduled_online_sources: bool = os.environ.get('SCHEDULED_ONLINE_SOURCES', 'true').lower() == 'true'
    
    # 超时设置
    request_timeout: int = 30
    proxy_test_timeout: int = 5
    
    # 并发设置
    verify_workers: int = 500
    max_http_proxies: int = int(os.environ.get('MAX_HTTP_PROXIES', '100'))
    max_per_source: int = int(os.environ.get('MAX_PER_SOURCE', '30'))


CFG = ParserConfig()

# 兼容旧代码
MAX_NODES = CFG.max_nodes
SUBSCRIPTIONS_FILE = CFG.subscriptions_file
HTTP_PROXIES_FILE = CFG.http_proxies_file
HTTPS_PROXIES_FILE = CFG.https_proxies_file
PROXY_SOURCES_FILE = CFG.proxy_sources_file
ENABLE_ONLINE_SOURCES = CFG.enable_online_sources
SCHEDULED_ONLINE_SOURCES = CFG.scheduled_online_sources


def _b64_decode(s: str) -> bytes:
    """Base64 解码，自动处理 padding"""
    s = s.strip().replace('-', '+').replace('_', '/')
    padding = (-len(s)) % 4
    return base64.b64decode(s + ('=' * padding))


def parse_ss(uri: str) -> Optional[Dict[str, Any]]:
    """解析 ss:// 链接"""
    try:
        uri = uri.strip()
        if not uri.startswith('ss://'):
            return None
        
        rest = uri[5:]
        tag = ''
        if '#' in rest:
            rest, tag = rest.rsplit('#', 1)
            tag = unquote(tag)
        
        # 格式1: ss://BASE64@host:port
        # 格式2: ss://method:password@host:port
        # 格式3: ss://BASE64 (完整编码)
        
        if '@' in rest:
            userinfo, hostport = rest.rsplit('@', 1)
            # 尝试解码 userinfo
            if ':' not in userinfo:
                try:
                    userinfo = _b64_decode(userinfo).decode('utf-8')
                except:
                    pass
            if ':' not in userinfo:
                return None
            method, password = userinfo.split(':', 1)
            host, port = hostport.split(':')
        else:
            # 完整 base64 编码
            try:
                decoded = _b64_decode(rest).decode('utf-8')
                if '@' not in decoded:
                    return None
                userinfo, hostport = decoded.rsplit('@', 1)
                method, password = userinfo.split(':', 1)
                host, port = hostport.split(':')
            except:
                return None
        
        return {
            'type': 'shadowsocks',
            'tag': tag or f'ss-{host}',
            'server': host,
            'server_port': int(port),
            'method': method,
            'password': password
        }
    except Exception:
        return None


def parse_vmess(uri: str) -> Optional[Dict[str, Any]]:
    """解析 vmess:// 链接"""
    try:
        if not uri.startswith('vmess://'):
            return None
        
        payload = uri[8:]
        if '#' in payload:
            payload = payload.split('#')[0]
        
        raw = _b64_decode(payload).decode('utf-8')
        data = json.loads(raw)
        
        server = str(data.get('add', '')).strip()
        port = int(data.get('port', 0))
        uuid = str(data.get('id', '')).strip()
        
        if not (server and port and uuid):
            return None
        
        outbound = {
            'type': 'vmess',
            'tag': data.get('ps', f'vmess-{server}'),
            'server': server,
            'server_port': port,
            'uuid': uuid,
            'security': data.get('scy', 'auto'),
            'alter_id': int(data.get('aid', 0))
        }
        
        # TLS
        if data.get('tls') == 'tls':
            outbound['tls'] = {
                'enabled': True,
                'server_name': data.get('sni', server)
            }
        
        # Transport
        net = data.get('net', 'tcp')
        if net == 'ws':
            outbound['transport'] = {
                'type': 'ws',
                'path': data.get('path', '/'),
                'headers': {'Host': data.get('host', server)}
            }
        elif net == 'grpc':
            outbound['transport'] = {
                'type': 'grpc',
                'service_name': data.get('path', '')
            }
        
        return outbound
    except Exception:
        return None


def parse_vless(uri: str) -> Optional[Dict[str, Any]]:
    """解析 vless:// 链接"""
    try:
        if not uri.startswith('vless://'):
            return None
        
        parsed = urlparse(uri)
        uuid = parsed.username
        server = parsed.hostname
        port = parsed.port or 443
        
        if not (uuid and server):
            return None
        
        params = parse_qs(parsed.query)
        tag = unquote(parsed.fragment) if parsed.fragment else f'vless-{server}'
        
        outbound = {
            'type': 'vless',
            'tag': tag,
            'server': server,
            'server_port': port,
            'uuid': uuid
        }
        
        # TLS / Reality
        security = params.get('security', ['none'])[0]
        if security == 'tls':
            outbound['tls'] = {
                'enabled': True,
                'server_name': params.get('sni', [server])[0]
            }
            alpn = params.get('alpn', [])
            if alpn:
                outbound['tls']['alpn'] = alpn[0].split(',')
        elif security == 'reality':
            outbound['tls'] = {
                'enabled': True,
                'server_name': params.get('sni', [server])[0],
                'utls': {
                    'enabled': True,
                    'fingerprint': params.get('fp', ['chrome'])[0]
                },
                'reality': {
                    'enabled': True,
                    'public_key': params.get('pbk', [''])[0],
                    'short_id': params.get('sid', [''])[0]
                }
            }
        
        # Transport
        transport_type = params.get('type', ['tcp'])[0]
        if transport_type == 'ws':
            outbound['transport'] = {
                'type': 'ws',
                'path': params.get('path', ['/'])[0],
                'headers': {'Host': params.get('host', [server])[0]}
            }
        elif transport_type == 'grpc':
            outbound['transport'] = {
                'type': 'grpc',
                'service_name': params.get('serviceName', [''])[0]
            }
        
        return outbound
    except Exception:
        return None


def parse_trojan(uri: str) -> Optional[Dict[str, Any]]:
    """解析 trojan:// 链接"""
    try:
        if not uri.startswith('trojan://'):
            return None
        
        parsed = urlparse(uri)
        password = unquote(parsed.username) if parsed.username else ''
        server = parsed.hostname
        port = parsed.port or 443
        
        if not (password and server):
            return None
        
        params = parse_qs(parsed.query)
        tag = unquote(parsed.fragment) if parsed.fragment else f'trojan-{server}'
        
        outbound = {
            'type': 'trojan',
            'tag': tag,
            'server': server,
            'server_port': port,
            'password': password,
            'tls': {
                'enabled': True,
                'server_name': params.get('sni', [server])[0]
            }
        }
        
        # Transport
        transport_type = params.get('type', ['tcp'])[0]
        if transport_type == 'ws':
            outbound['transport'] = {
                'type': 'ws',
                'path': params.get('path', ['/'])[0]
            }
        elif transport_type == 'grpc':
            outbound['transport'] = {
                'type': 'grpc',
                'service_name': params.get('serviceName', [''])[0]
            }
        
        return outbound
    except Exception:
        return None


def parse_hysteria2(uri: str) -> Optional[Dict[str, Any]]:
    """解析 hysteria2:// 或 hy2:// 链接"""
    try:
        if uri.startswith('hy2://'):
            uri = 'hysteria2://' + uri[6:]
        if not uri.startswith('hysteria2://'):
            return None
        
        parsed = urlparse(uri)
        password = unquote(parsed.username) if parsed.username else ''
        server = parsed.hostname
        port = parsed.port or 443
        
        if not (password and server):
            return None
        
        params = parse_qs(parsed.query)
        tag = unquote(parsed.fragment) if parsed.fragment else f'hy2-{server}'
        
        outbound = {
            'type': 'hysteria2',
            'tag': tag,
            'server': server,
            'server_port': port,
            'password': password,
            'tls': {
                'enabled': True,
                'server_name': params.get('sni', [server])[0]
            }
        }
        
        # 可选参数
        if 'insecure' in params:
            outbound['tls']['insecure'] = params['insecure'][0] == '1'
        
        return outbound
    except Exception:
        return None


def sanitize_tag(tag: str, server: str, port: int) -> str:
    """清理 tag 名称，移除 sing-box 不支持的字符"""
    # 只保留字母、数字、下划线、连字符
    clean = re.sub(r'[^a-zA-Z0-9_\-]', '_', tag)
    # 移除连续下划线
    clean = re.sub(r'_+', '_', clean).strip('_')
    # 如果清理后为空或太短，使用 server:port
    if len(clean) < 3:
        clean = f"{server}_{port}"
    return clean[:50]  # 限制长度


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """解析单行代理链接"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    result = None
    if line.startswith('ss://'):
        result = parse_ss(line)
    elif line.startswith('vmess://'):
        result = parse_vmess(line)
    elif line.startswith('vless://'):
        result = parse_vless(line)
    elif line.startswith('trojan://'):
        result = parse_trojan(line)
    elif line.startswith(('hysteria2://', 'hy2://')):
        result = parse_hysteria2(line)
    
    # 清理 tag
    if result:
        result['tag'] = sanitize_tag(
            result.get('tag', ''),
            result.get('server', 'unknown'),
            result.get('server_port', 0)
        )
    
    return result


def parse_clash_proxies(proxies: List[Dict]) -> List[Dict[str, Any]]:
    """解析 Clash YAML 中的 proxies"""
    outbounds = []
    
    for p in proxies:
        ptype = p.get('type', '').lower()
        server = p.get('server', '')
        port = int(p.get('port', 0))
        
        try:
            if ptype == 'ss':
                outbound = {
                    'type': 'shadowsocks',
                    'tag': sanitize_tag(p.get('name', ''), server, port),
                    'server': server,
                    'server_port': port,
                    'method': p['cipher'],
                    'password': p['password']
                }
                outbounds.append(outbound)
            
            elif ptype == 'vmess':
                outbound = {
                    'type': 'vmess',
                    'tag': sanitize_tag(p.get('name', ''), server, port),
                    'server': server,
                    'server_port': port,
                    'uuid': p['uuid'],
                    'security': p.get('cipher', 'auto'),
                    'alter_id': int(p.get('alterId', 0))
                }
                if p.get('tls'):
                    outbound['tls'] = {'enabled': True, 'server_name': p.get('servername', server)}
                if p.get('network') == 'ws':
                    outbound['transport'] = {
                        'type': 'ws',
                        'path': p.get('ws-opts', {}).get('path', '/'),
                        'headers': p.get('ws-opts', {}).get('headers', {})
                    }
                outbounds.append(outbound)
            
            elif ptype == 'vless':
                outbound = {
                    'type': 'vless',
                    'tag': sanitize_tag(p.get('name', ''), server, port),
                    'server': server,
                    'server_port': port,
                    'uuid': p['uuid']
                }
                if p.get('tls'):
                    outbound['tls'] = {'enabled': True, 'server_name': p.get('servername', server)}
                if p.get('network') == 'ws':
                    outbound['transport'] = {
                        'type': 'ws',
                        'path': p.get('ws-opts', {}).get('path', '/')
                    }
                outbounds.append(outbound)
            
            elif ptype == 'trojan':
                outbound = {
                    'type': 'trojan',
                    'tag': sanitize_tag(p.get('name', ''), server, port),
                    'server': server,
                    'server_port': port,
                    'password': p['password'],
                    'tls': {'enabled': True, 'server_name': p.get('sni', server)}
                }
                outbounds.append(outbound)
            
            elif ptype == 'hysteria2':
                outbound = {
                    'type': 'hysteria2',
                    'tag': sanitize_tag(p.get('name', ''), server, port),
                    'server': server,
                    'server_port': port,
                    'password': p.get('password', p.get('auth', '')),
                    'tls': {'enabled': True, 'server_name': p.get('sni', server)}
                }
                outbounds.append(outbound)
        except Exception:
            continue
    
    return outbounds


def fetch_subscription(url: str) -> List[Dict[str, Any]]:
    """获取并解析订阅"""
    if requests is None:
        return []
    
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        resp = requests.get(url, timeout=CFG.request_timeout, verify=False)
        resp.raise_for_status()
        text = resp.text.strip()
        
        # 尝试解析为 YAML
        if text.startswith('proxies:') or 'proxies:' in text[:200]:
            data = yaml.safe_load(text)
            if data and 'proxies' in data:
                return parse_clash_proxies(data['proxies'])
        
        # 尝试 base64 解码
        try:
            if re.fullmatch(r'[A-Za-z0-9+/=_-]+', ''.join(text.split())):
                text = _b64_decode(text).decode('utf-8', errors='ignore')
        except:
            pass
        
        # 逐行解析
        outbounds = []
        for line in text.splitlines():
            ob = parse_line(line)
            if ob:
                outbounds.append(ob)
        
        return outbounds
    except Exception as e:
        print(f"获取订阅失败 {url[:50]}...: {e}")
        return []


def read_subscriptions() -> List[str]:
    """读取订阅文件"""
    path = Path(SUBSCRIPTIONS_FILE)
    if not path.exists():
        return []
    urls = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                urls.append(line)
    return urls


def test_http_proxy(proxy_info: tuple, timeout: int = 3) -> Optional[tuple]:
    """测试 HTTP 代理是否支持 HTTPS 流量，返回 (host, port, user, pass) 或 None"""
    if requests is None:
        return None
    
    host, port, username, password = proxy_info
    
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        proxy_url = f"http://{host}:{port}"
        if username and password:
            proxy_url = f"http://{username}:{password}@{host}:{port}"
        
        proxies = {'http': proxy_url, 'https': proxy_url}
        resp = requests.get(
            'https://www.google.com/generate_204',
            proxies=proxies,
            timeout=timeout,
            verify=False
        )
        if resp.status_code == 204:
            return proxy_info
    except Exception:
        pass
    return None


def test_socks_proxy(proxy_info: tuple, proxy_type: str = 'socks5', timeout: int = 5) -> Optional[tuple]:
    """测试 SOCKS 代理是否可用"""
    if requests is None:
        return None
    
    host, port, username, password = proxy_info
    
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        proxy_url = f"{proxy_type}://{host}:{port}"
        if username and password:
            proxy_url = f"{proxy_type}://{username}:{password}@{host}:{port}"
        
        proxies = {'http': proxy_url, 'https': proxy_url}
        resp = requests.get(
            'https://www.google.com/generate_204',
            proxies=proxies,
            timeout=timeout,
            verify=False
        )
        if resp.status_code == 204:
            return proxy_info
    except Exception:
        pass
    return None


def fetch_proxy_list_from_url(url: str) -> List[tuple]:
    """从 URL 获取代理列表（ip:port 格式）"""
    if requests is None:
        return []
    
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        resp = requests.get(url, timeout=CFG.request_timeout, verify=False)
        resp.raise_for_status()
        
        proxy_list = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                parts = line.split(':')
                if len(parts) >= 2:
                    host = parts[0]
                    port = int(parts[1])
                    username = parts[2] if len(parts) >= 4 else None
                    password = parts[3] if len(parts) >= 4 else None
                    proxy_list.append((host, port, username, password))
            except:
                continue
        
        return proxy_list
    except Exception as e:
        print(f"  ✗ 获取失败 {url[:50]}...: {e}")
        return []


def load_proxies_from_sources(verify: bool = True, max_per_source: int = 50) -> List[Dict[str, Any]]:
    """从 proxy_sources.txt 中的 URL 加载代理"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    path = Path(PROXY_SOURCES_FILE)
    if not path.exists():
        return []
    
    # 读取源配置
    sources = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # 格式: type|url 或直接 url（默认 http）
            if '|' in line:
                ptype, url = line.split('|', 1)
            else:
                url = line
                # 自动检测类型
                if 'socks5' in url.lower():
                    ptype = 'socks5'
                elif 'socks4' in url.lower():
                    ptype = 'socks4'
                elif 'https' in url.lower() and 'http.txt' not in url.lower():
                    ptype = 'https'
                else:
                    ptype = 'http'
            sources.append((ptype.strip(), url.strip()))
    
    if not sources:
        return []
    
    print(f"从 {len(sources)} 个在线源获取代理...")
    
    all_outbounds = []
    
    for ptype, url in sources:
        print(f"  获取 {ptype.upper()}: {url[:60]}...")
        proxy_list = fetch_proxy_list_from_url(url)
        
        if not proxy_list:
            continue
        
        print(f"    获取到 {len(proxy_list)} 个，开始验证...")
        
        # 根据类型选择测试函数
        if ptype in ('socks4', 'socks5'):
            test_func = lambda p, pt=ptype: test_socks_proxy(p, pt, timeout=CFG.proxy_test_timeout)
        else:
            test_func = lambda p: test_http_proxy(p, timeout=CFG.proxy_test_timeout)
        
        # 并发验证（验证所有，然后取前 max_per_source 个）
        valid_proxies = []
        if verify:
            with ThreadPoolExecutor(max_workers=CFG.verify_workers) as executor:
                futures = {executor.submit(test_func, p): p for p in proxy_list}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        valid_proxies.append(result)
            print(f"    ✓ 验证通过: {len(valid_proxies)}/{len(proxy_list)}")
            # 只保留前 max_per_source 个
            if len(valid_proxies) > max_per_source:
                valid_proxies = valid_proxies[:max_per_source]
                print(f"    ℹ 限制为 {max_per_source} 个")
        else:
            valid_proxies = proxy_list[:max_per_source]
        
        # 转换为 outbound 格式
        for host, port, username, password in valid_proxies:
            if ptype in ('socks4', 'socks5'):
                outbound = {
                    'type': 'socks',
                    'tag': f'{ptype}_{host}_{port}',
                    'server': host,
                    'server_port': port,
                    'version': '4' if ptype == 'socks4' else '5'
                }
                if username and password and ptype == 'socks5':
                    outbound['username'] = username
                    outbound['password'] = password
            else:
                outbound = {
                    'type': 'http',
                    'tag': f'{ptype}_{host}_{port}',
                    'server': host,
                    'server_port': port
                }
                if username and password:
                    outbound['username'] = username
                    outbound['password'] = password
                if ptype == 'https':
                    outbound['tls'] = {'enabled': True, 'insecure': True}
            
            all_outbounds.append(outbound)
    
    return all_outbounds


def load_http_proxies(filepath: str, use_tls: bool = False, verify: bool = True, max_proxies: int = 100) -> List[Dict[str, Any]]:
    """从文件加载 HTTP/HTTPS 代理，并发验证可用性"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    path = Path(filepath)
    if not path.exists():
        return []
    
    proxy_type = 'https' if use_tls else 'http'
    
    # 解析代理列表
    proxy_list = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                parts = line.split(':')
                if len(parts) >= 2:
                    host = parts[0]
                    port = int(parts[1])
                    username = parts[2] if len(parts) >= 4 else None
                    password = parts[3] if len(parts) >= 4 else None
                    proxy_list.append((host, port, username, password))
            except Exception:
                continue
    
    if not proxy_list:
        return []
    
    print(f"  检测 {proxy_type.upper()} 代理 ({len(proxy_list)} 个)...", flush=True)
    
    # 并发测试
    valid_proxies = []
    if verify:
        with ThreadPoolExecutor(max_workers=CFG.verify_workers) as executor:
            futures = {executor.submit(test_http_proxy, p): p for p in proxy_list}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    valid_proxies.append(result)
                    if len(valid_proxies) >= max_proxies:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
        print(f"    通过 {len(valid_proxies)}/{len(proxy_list)} 个", flush=True)
    else:
        valid_proxies = proxy_list[:max_proxies]
    
    # 转换为 outbound 格式
    outbounds = []
    for host, port, username, password in valid_proxies:
        outbound = {
            'type': 'http',
            'tag': f'{proxy_type}_{host}_{port}',
            'server': host,
            'server_port': port
        }
        if username and password:
            outbound['username'] = username
            outbound['password'] = password
        if use_tls:
            outbound['tls'] = {'enabled': True, 'insecure': True}
        outbounds.append(outbound)
    
    return outbounds


def fetch_all_subscriptions() -> tuple:
    """获取所有订阅，返回 (outbounds, stats)"""
    urls = read_subscriptions()
    
    all_outbounds = []
    stats = {'total_urls': len(urls), 'ok': 0, 'failed': 0, 'nodes': 0, 'by_type': {}}
    
    # 加载 HTTP/HTTPS 代理文件（验证可用性，限制数量）
    verify_proxies = os.environ.get('VERIFY_HTTP_PROXIES', 'true').lower() == 'true'
    max_http = int(os.environ.get('MAX_HTTP_PROXIES', '100'))
    
    http_proxies = load_http_proxies(HTTP_PROXIES_FILE, use_tls=False, verify=verify_proxies, max_proxies=max_http)
    https_proxies = load_http_proxies(HTTPS_PROXIES_FILE, use_tls=True, verify=verify_proxies, max_proxies=max_http)
    
    if http_proxies:
        print(f"  ✓ HTTP 代理可用: {len(http_proxies)} 个")
        all_outbounds.extend(http_proxies)
    
    if https_proxies:
        print(f"  ✓ HTTPS 代理可用: {len(https_proxies)} 个")
        all_outbounds.extend(https_proxies)
    
    # 从在线源加载代理（可选，默认禁用因为数量太大）
    # 可通过参数 force_online 强制加载（用于定时任务）
    load_online = ENABLE_ONLINE_SOURCES
    if 'FORCE_ONLINE_SOURCES' in os.environ:
        load_online = os.environ.get('FORCE_ONLINE_SOURCES', 'false').lower() == 'true'
        del os.environ['FORCE_ONLINE_SOURCES']  # 用完删除
    
    if load_online:
        max_per_source = int(os.environ.get('MAX_PER_SOURCE', '30'))
        online_proxies = load_proxies_from_sources(verify=verify_proxies, max_per_source=max_per_source)
        if online_proxies:
            print(f"  ✓ 在线源代理可用: {len(online_proxies)} 个")
            all_outbounds.extend(online_proxies)
    else:
        print("  ℹ 在线代理源已禁用")
    
    if not urls and not all_outbounds:
        return [], stats
    
    print(f"开始获取 {len(urls)} 个订阅...")
    
    for url in urls:
        outbounds = fetch_subscription(url)
        if outbounds:
            all_outbounds.extend(outbounds)
            stats['ok'] += 1
            print(f"  ✓ {url[:50]}... ({len(outbounds)} 节点)")
        else:
            stats['failed'] += 1
            print(f"  ✗ {url[:50]}...")
    
    # 去重（基于 server:port）并确保 tag 唯一
    seen_keys = set()
    seen_tags = set()
    unique = []
    for ob in all_outbounds:
        key = f"{ob.get('server')}:{ob.get('server_port')}"
        if key not in seen_keys:
            seen_keys.add(key)
            # 确保 tag 唯一
            tag = ob.get('tag', '')
            if tag in seen_tags:
                tag = f"{tag}_{len(unique)}"
                ob['tag'] = tag
            seen_tags.add(tag)
            unique.append(ob)
            # 统计类型
            t = ob.get('type', 'unknown')
            stats['by_type'][t] = stats['by_type'].get(t, 0) + 1
    
    # 限制数量
    if len(unique) > MAX_NODES:
        print(f"节点过多 ({len(unique)})，限制为 {MAX_NODES}")
        unique = unique[:MAX_NODES]
    
    stats['nodes'] = len(unique)
    stats['before_dedup'] = len(all_outbounds)
    
    return unique, stats
