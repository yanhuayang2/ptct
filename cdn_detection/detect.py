import requests
from urllib.parse import urlparse

class CDNDetector:
    def __init__(self, cdn_file='cdn_detection/cdn_providers.txt'):
        self.cdn_providers = self.load_cdn_providers(cdn_file)

    def load_cdn_providers(self, cdn_file):
        cdn_providers = {}
        with open(cdn_file, 'r', encoding='utf-8') as file:
            current_provider = None
            for line in file:
                line = line.strip()
                if not line:
                    current_provider = None
                    continue
                if current_provider is None:
                    current_provider = line
                    cdn_providers[current_provider] = []
                else:
                    cdn_providers[current_provider].append(line)
        return cdn_providers

    def extract_domain(self, url):
        parsed_url = urlparse(url)
        return parsed_url.netloc or parsed_url.path.split('/')[0]

    def is_using_cdn(self, domain):
        try:
            domain = self.extract_domain(domain)
            response = requests.head(f"https://{domain}", timeout=5)
            headers = response.headers

            # Check for CDN provider
            for provider, identifiers in self.cdn_providers.items():
                for identifier in identifiers:
                    if identifier in headers.get('server', '').lower() or identifier in headers or identifier in domain:
                        return f"CDN detected: [{provider}]."

            server_header = headers.get('server', None)
            if server_header:
                return f"No CDN detected and server header found: {server_header}."
        except (requests.exceptions.RequestException, requests.exceptions.ConnectionError):
            pass

        return "No CDN detected and no server header found."

    def detect(self, domain):
        result = self.is_using_cdn(domain)
        print(f"[+] The domain {domain} detection result: \n[+] {result}")
