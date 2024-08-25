import argparse
from cdn_detection import CDNDetector
from subdomain_scan import SubDomainScanner
from ip_discovery import IpHistorical
from waf_detection import WAFDetector
from port_scan import PortScanner
import asyncio


def sub_scan(domain, threads):
    print(f"[+] Scanning subdomain of {domain}...")
    wordlist_path = 'subdomain_scan/sub_wordlist.txt'  # 字典文件路径
    output_dir = 'subdomain_scan/subdomain_output'  # 输出目录
    dns_servers = ["8.8.8.8", "8.8.4.4", "114.114.114.114", "114.114.115.115", "223.5.5.5",
                   "223.6.6.6", "180.76.76.76", "119.29.29.29", "182.254.116.116"]

    scanner = SubDomainScanner(domain, wordlist_path, output_dir, threads, dns_servers)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(scanner.run())


def port_scan(target):
    common_ports = '20,21,22,23,25,53,67,68,80,110,143,161,162,443,445,465,587,993,995,3389'
    scanner = PortScanner(target, common_ports)
    results = scanner.run()
    for port, status in results:
        if status == 'open':
            print(f"[+] Port {port} is {status}")
        else:
            print(f"[-] Port {port} is {status}")

def waf_detect(domain):
    print(f"[+] Detecting WAF of {domain}...")
    detector = WAFDetector(domain)
    detector.run()


def main():
    parser = argparse.ArgumentParser(description="Network security penetration testing tool")
    parser.add_argument('-c', '--cdn', help='Detect CDN', type=str)
    parser.add_argument('-s', '--subdomains', help='Brute force subdomains', type=str)
    parser.add_argument('-t', '--threads', help='The number of threads in the scanner', type=int, default=20)
    parser.add_argument('-i', '--ip', help='Find ip historical', type=str)
    parser.add_argument('-w', '--waf', help='Detect WAF', type=str)
    parser.add_argument('-p', '--portscan',help='Port scan', type=str)
    args = parser.parse_args()

    if args.cdn:
        cdn_detector = CDNDetector()
        cdn_detector.detect(args.cdn)

    if args.ip:
        find_ip = IpHistorical()
        find_ip.get_historical_ip(args.ip)

    if args.subdomains:
        sub_scan(args.subdomains, args.threads)

    if args.waf:
        waf_detect(args.waf)

    if args.portscan:
        port_scan(args.portscan)

if __name__ == '__main__':
    main()
