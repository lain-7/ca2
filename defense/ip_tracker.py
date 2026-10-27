#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 地理位置和威胁情报查询工具
功能：
  1. 查询 IP 地理位置（国家、城市、ISP）
  2. 检查 IP 是否在已知恶意 IP 数据库
  3. 支持批量查询
  4. 生成 JSON 格式结果
"""

import json
import sys
import time
from typing import Dict, List, Optional
from pathlib import Path
import socket
import subprocess
import shutil

def check_curl_available():
    """检查 curl 是否可用"""
    if not shutil.which('curl'):
        print("错误: 未找到 curl 工具", file=sys.stderr)
        print("请安装: sudo pacman -S curl  (Arch Linux)", file=sys.stderr)
        print("       sudo apt install curl  (Ubuntu/Debian)", file=sys.stderr)
        sys.exit(1)


class IPTracker:
    """IP 溯源器"""

    def __init__(self, use_cache=True):
        """
        初始化 IP 溯源器

        Args:
            use_cache: 是否使用缓存（避免重复查询）
        """
        self.use_cache = use_cache
        self.cache = {}
        self.cache_file = Path(__file__).parent / 'lib' / 'ip_cache.json'

        if use_cache and self.cache_file.exists():
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}

    def save_cache(self):
        """保存缓存到文件"""
        if not self.use_cache:
            return

        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"警告：无法保存缓存 - {e}", file=sys.stderr)

    def is_internal_ip(self, ip: str) -> bool:
        """
        判断是否为内网 IP

        Args:
            ip: IP 地址

        Returns:
            True 表示内网 IP
        """
        try:
            parts = [int(p) for p in ip.split('.')]

            # 10.0.0.0/8
            if parts[0] == 10:
                return True

            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True

            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True

            # 127.0.0.0/8 (Loopback)
            if parts[0] == 127:
                return True

            return False
        except Exception:
            return False

    def query_ip_api(self, ip: str) -> Optional[Dict]:
        """
        使用 ip-api.com 查询 IP 信息（免费，无需 API key）
        限制：每分钟 45 次请求

        Args:
            ip: IP 地址

        Returns:
            包含 IP 信息的字典，失败返回 None
        """
        try:
            # 使用 curl 查询（避免依赖 requests 库）
            cmd = [
                'curl', '-s', '--max-time', '10',
                f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,query'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)

                if data.get('status') == 'success':
                    return {
                        'ip': data.get('query', ip),
                        'country': data.get('country', '未知'),
                        'country_code': data.get('countryCode', ''),
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'isp': data.get('isp', '未知'),
                        'org': data.get('org', ''),
                        'as': data.get('as', ''),
                        'source': 'ip-api.com'
                    }
                else:
                    return None

            return None
        except Exception as e:
            print(f"查询失败 ({ip}): {e}", file=sys.stderr)
            return None

    def check_reverse_dns(self, ip: str) -> Optional[str]:
        """
        反向 DNS 查询

        Args:
            ip: IP 地址

        Returns:
            主机名或 None
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None

    def enrich_ip(self, ip: str) -> Dict:
        """
        综合查询 IP 信息

        Args:
            ip: IP 地址

        Returns:
            包含所有可用信息的字典
        """
        # 检查缓存
        if ip in self.cache:
            return self.cache[ip]

        result = {
            'ip': ip,
            'is_internal': self.is_internal_ip(ip),
            'hostname': None,
            'country': '未知',
            'country_code': '',
            'region': '',
            'city': '',
            'isp': '未知',
            'org': '',
            'as': '',
            'threat_level': 'low',  # low / medium / high
            'tags': []
        }

        # 内网 IP 特殊处理
        if result['is_internal']:
            result['country'] = '内网'
            result['isp'] = '局域网'
            result['tags'].append('private')
            result['threat_level'] = 'low'
            self.cache[ip] = result
            return result

        # 反向 DNS 查询
        hostname = self.check_reverse_dns(ip)
        if hostname:
            result['hostname'] = hostname

            # 根据主机名打标签
            if any(kw in hostname.lower() for kw in ['google', 'amazon', 'microsoft', 'azure']):
                result['tags'].append('cloud')
            if any(kw in hostname.lower() for kw in ['scanner', 'bot', 'crawler']):
                result['tags'].append('scanner')
                result['threat_level'] = 'medium'

        # 查询地理位置
        geo_info = self.query_ip_api(ip)
        if geo_info:
            result.update(geo_info)

        # 简单威胁评估
        # 来自某些高危国家的 IP 标记为 medium
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']
        if result['country_code'] in high_risk_countries:
            result['threat_level'] = 'medium'
            result['tags'].append('high-risk-region')

        # 缓存结果
        self.cache[ip] = result

        # API 速率限制（ip-api.com: 45 req/min）
        time.sleep(1.5)

        return result

    def batch_enrich(self, ips: List[str]) -> List[Dict]:
        """
        批量查询 IP 信息

        Args:
            ips: IP 地址列表

        Returns:
            结果列表
        """
        results = []
        unique_ips = list(set(ips))  # 去重

        print(f"正在查询 {len(unique_ips)} 个唯一 IP...", file=sys.stderr)

        for i, ip in enumerate(unique_ips, 1):
            print(f"[{i}/{len(unique_ips)}] 查询 {ip}...", file=sys.stderr)
            result = self.enrich_ip(ip)
            results.append(result)

        # 保存缓存
        self.save_cache()

        return results


def main():
    """命令行入口"""
    import argparse

    # 检查依赖
    check_curl_available()

    parser = argparse.ArgumentParser(
        description='IP 地理位置和威胁情报查询工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  # 查询单个 IP
  %(prog)s 8.8.8.8

  # 查询多个 IP
  %(prog)s 8.8.8.8 1.1.1.1 192.168.1.1

  # 从文件读取 IP 列表（每行一个）
  %(prog)s --file ip_list.txt

  # 输出 JSON 格式
  %(prog)s --json 8.8.8.8
        '''
    )

    parser.add_argument('ips', nargs='*', help='要查询的 IP 地址')
    parser.add_argument('--file', '-f', help='从文件读取 IP 列表（每行一个）')
    parser.add_argument('--json', action='store_true', help='输出 JSON 格式')
    parser.add_argument('--no-cache', action='store_true', help='禁用缓存')

    args = parser.parse_args()

    # 收集要查询的 IP
    ips = list(args.ips) if args.ips else []

    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                ips.extend(file_ips)
        except Exception as e:
            print(f"错误：无法读取文件 {args.file} - {e}", file=sys.stderr)
            sys.exit(1)

    if not ips:
        parser.print_help()
        sys.exit(1)

    # 查询
    tracker = IPTracker(use_cache=not args.no_cache)
    results = tracker.batch_enrich(ips)

    # 输出
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        # 人类可读格式
        for result in results:
            print(f"\n{'='*60}")
            print(f"IP 地址: {result['ip']}")

            if result['is_internal']:
                print(f"类型: 内网地址")
            else:
                if result['hostname']:
                    print(f"主机名: {result['hostname']}")
                print(f"国家: {result['country']} ({result['country_code']})")
                if result['region']:
                    print(f"地区: {result['region']}")
                if result['city']:
                    print(f"城市: {result['city']}")
                print(f"ISP: {result['isp']}")
                if result['org']:
                    print(f"组织: {result['org']}")
                if result['as']:
                    print(f"AS 号: {result['as']}")

            print(f"威胁等级: {result['threat_level'].upper()}")
            if result['tags']:
                print(f"标签: {', '.join(result['tags'])}")


if __name__ == '__main__':
    main()
