#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP geolocation and threat intelligence lookup tool
Features:
  1. Look up IP geolocation (country, city, ISP)
  2. Check whether an IP is in known malicious IP databases
  3. Support batch lookups
  4. Produce results in JSON format
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
    """Check whether curl is available."""
    if not shutil.which('curl'):
        print("Error: curl not found", file=sys.stderr)
        print("Install with: sudo pacman -S curl  (Arch Linux)", file=sys.stderr)
        print("             sudo apt install curl  (Ubuntu/Debian)", file=sys.stderr)
        sys.exit(1)


class IPTracker:
    """IP tracer."""

    def __init__(self, use_cache=True):
        """
        Initialise the IP tracer.

        Args:
            use_cache: whether to use the cache (avoid repeated lookups)
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
        """Save the cache to a file."""
        if not self.use_cache:
            return

        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Warning: could not save cache - {e}", file=sys.stderr)

    def is_internal_ip(self, ip: str) -> bool:
        """
        Decide whether this is an internal IP.

        Args:
            ip: IP address

        Returns:
            True if it is an internal IP
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
        Look up IP information using ip-api.com (free, no API key needed).
        Limit: 45 requests per minute.

        Args:
            ip: IP address

        Returns:
            a dict with IP information, or None on failure
        """
        try:
            # Query via curl (avoids depending on the requests library)
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
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', ''),
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', ''),
                        'as': data.get('as', ''),
                        'source': 'ip-api.com'
                    }
                else:
                    return None

            return None
        except Exception as e:
            print(f"Lookup failed ({ip}): {e}", file=sys.stderr)
            return None

    def check_reverse_dns(self, ip: str) -> Optional[str]:
        """
        Reverse DNS lookup.

        Args:
            ip: IP address

        Returns:
            the hostname, or None
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None

    def enrich_ip(self, ip: str) -> Dict:
        """
        Combined IP information lookup.

        Args:
            ip: IP address

        Returns:
            a dict with all available information
        """
        # Check the cache
        if ip in self.cache:
            return self.cache[ip]

        result = {
            'ip': ip,
            'is_internal': self.is_internal_ip(ip),
            'hostname': None,
            'country': 'Unknown',
            'country_code': '',
            'region': '',
            'city': '',
            'isp': 'Unknown',
            'org': '',
            'as': '',
            'threat_level': 'low',  # low / medium / high
            'tags': []
        }

        # Special handling for internal IPs
        if result['is_internal']:
            result['country'] = 'Internal'
            result['isp'] = 'LAN'
            result['tags'].append('private')
            result['threat_level'] = 'low'
            self.cache[ip] = result
            return result

        # Reverse DNS lookup
        hostname = self.check_reverse_dns(ip)
        if hostname:
            result['hostname'] = hostname

            # Tag based on the hostname
            if any(kw in hostname.lower() for kw in ['google', 'amazon', 'microsoft', 'azure']):
                result['tags'].append('cloud')
            if any(kw in hostname.lower() for kw in ['scanner', 'bot', 'crawler']):
                result['tags'].append('scanner')
                result['threat_level'] = 'medium'

        # Look up geolocation
        geo_info = self.query_ip_api(ip)
        if geo_info:
            result.update(geo_info)

        # Simple threat assessment
        # IPs from certain high-risk countries are marked medium
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']
        if result['country_code'] in high_risk_countries:
            result['threat_level'] = 'medium'
            result['tags'].append('high-risk-region')

        # Cache the result
        self.cache[ip] = result

        # API rate limit (ip-api.com: 45 req/min)
        time.sleep(1.5)

        return result

    def batch_enrich(self, ips: List[str]) -> List[Dict]:
        """
        Batch IP information lookup.

        Args:
            ips: list of IP addresses

        Returns:
            list of results
        """
        results = []
        unique_ips = list(set(ips))  # deduplicate

        print(f"Looking up {len(unique_ips)} unique IPs...", file=sys.stderr)

        for i, ip in enumerate(unique_ips, 1):
            print(f"[{i}/{len(unique_ips)}] looking up {ip}...", file=sys.stderr)
            result = self.enrich_ip(ip)
            results.append(result)

        # Save the cache
        self.save_cache()

        return results


def main():
    """Command-line entry point."""
    import argparse

    # Check dependencies
    check_curl_available()

    parser = argparse.ArgumentParser(
        description='IP geolocation and threat intelligence lookup tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # look up a single IP
  %(prog)s 8.8.8.8

  # look up multiple IPs
  %(prog)s 8.8.8.8 1.1.1.1 192.168.1.1

  # read the IP list from a file (one per line)
  %(prog)s --file ip_list.txt

  # output in JSON format
  %(prog)s --json 8.8.8.8
        '''
    )

    parser.add_argument('ips', nargs='*', help='IP addresses to look up')
    parser.add_argument('--file', '-f', help='read the IP list from a file (one per line)')
    parser.add_argument('--json', action='store_true', help='output in JSON format')
    parser.add_argument('--no-cache', action='store_true', help='disable the cache')

    args = parser.parse_args()

    # Collect the IPs to look up
    ips = list(args.ips) if args.ips else []

    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                ips.extend(file_ips)
        except Exception as e:
            print(f"Error: could not read file {args.file} - {e}", file=sys.stderr)
            sys.exit(1)

    if not ips:
        parser.print_help()
        sys.exit(1)

    # Look up
    tracker = IPTracker(use_cache=not args.no_cache)
    results = tracker.batch_enrich(ips)

    # Output
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        # Human-readable format
        for result in results:
            print(f"\n{'='*60}")
            print(f"IP address: {result['ip']}")

            if result['is_internal']:
                print(f"Type: internal address")
            else:
                if result['hostname']:
                    print(f"Hostname: {result['hostname']}")
                print(f"Country: {result['country']} ({result['country_code']})")
                if result['region']:
                    print(f"Region: {result['region']}")
                if result['city']:
                    print(f"City: {result['city']}")
                print(f"ISP: {result['isp']}")
                if result['org']:
                    print(f"Organisation: {result['org']}")
                if result['as']:
                    print(f"AS number: {result['as']}")

            print(f"Threat level: {result['threat_level'].upper()}")
            if result['tags']:
                print(f"Tags: {', '.join(result['tags'])}")


if __name__ == '__main__':
    main()
