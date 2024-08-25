import requests
from bs4 import BeautifulSoup
import socket

class IpHistorical:
    def __int__(self):
        pass

    def get_ip_address(self, domain):
        try:
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except socket.gaierror as e:
            return f"IP resolution failed.\nError: {e}"

    def get_historical_ip(self, domain):
        resolved_ip = self.get_ip_address(domain)
        print(f"[+] Currently resolved IP: {resolved_ip}")
        try:
            url = f"https://viewdns.info/iphistory/?domain={domain}"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",

            }
            response = requests.get(url, headers=headers)
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            table = soup.find('table', {'border': '1'})

            if table:
                rows = table.find_all('tr')[2:]
                print(
                    f"\n[+] Historical IP Address Info from Viewdns for {domain}:")
                for row in rows:
                    columns = row.find_all('td')
                    ip_address = columns[0].text.strip()
                    location = columns[1].text.strip()
                    owner = columns[2].text.strip()
                    last_seen = columns[3].text.strip()
                    print(f"\n [+] IP Address: {ip_address}")
                    print(f"  - Location: {location}")
                    print(f"  - Owner: {owner}")
                    print(f"  - Last Seen: {last_seen}")
            else:
                print("[+] No record was found, check your network or visit https://viewdns.info/iphistory/.")
        except:
            None

