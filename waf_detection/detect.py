import json
import os
import re
from urllib.parse import urlparse
import socket
from urllib.request import Request, urlopen
import random
import re
import time
import difflib
from urllib.parse import quote


class WAFDetector:
    def __init__(self, url):
        self.url = url
        with open('waf_detection/config.json', 'r') as file:
            config = json.load(file)
        self.timeout = config.get('timeout', 10)
        self.delay = config.get('delay', 0)
        self.HEADERS = config.get('headers', {})
        self.ENCODING_TRANSLATIONS = config.get('encoding_translations', {})
        self.GENERIC_PROTECTION_KEYWORDS = config.get("generic_protection_keywords")
        self.GENERIC_PROTECTION_REGEX = config.get("generic_protection_regex")
        self.GENERIC_ERROR_MESSAGE_REGEX = config.get("generic_error_message_regex")
        self.HEURISTIC_PAYLOAD = config.get("heuristic_payload")
        self.non_blind = set()
        self.WAF_RECOGNITION_REGEX = ""
        self.DATA_JSON = {}
        self.SIGNATURES = {}
        self.load_data()
        self.intrusive = None

    def load_data(self):
        DATA_JSON_FILE = 'waf_detection/data.json'
        if not os.path.isfile(DATA_JSON_FILE):
            print(f"[x] File '{DATA_JSON_FILE}' is missing")
            exit(1)

        with open(DATA_JSON_FILE, "r", encoding="utf-8") as f:
            self.DATA_JSON.update(json.load(f))

        regex_patterns = []
        for waf, details in self.DATA_JSON.get("wafs", {}).items():
            if details.get("regex"):
                regex_patterns.append(f"(?P<waf_{waf}>{details['regex']})")
            for signature in details.get("signatures", []):
                self.SIGNATURES[signature] = waf

        self.WAF_RECOGNITION_REGEX = "|".join(regex_patterns)
        flags = "".join(set(m.group(1) for m in re.finditer(r"\(\?(\w+)\)", self.WAF_RECOGNITION_REGEX)))
        self.WAF_RECOGNITION_REGEX = re.sub(r"\(\?\w+\)", "", self.WAF_RECOGNITION_REGEX)
        if flags:
            self.WAF_RECOGNITION_REGEX = f"(?{flags}){self.WAF_RECOGNITION_REGEX}"

    def retrieve(self, payload_url=None):
        if payload_url is None:
            url = self.url
        else:
            url = payload_url
        retval = {}
        formatted_url = "".join(
            url[i].replace(' ', "%20") if i > url.find('?') else url[i]
            for i in range(len(url))
        )
        #print(f'[i] INFO:formatted_url: {formatted_url}')
        try:
            req = Request(formatted_url, headers=self.HEADERS)
            resp = urlopen(req, timeout=self.timeout)
            retval['URL'] = resp.url
            retval['HTML'] = resp.read()
            retval['HTTPCODE'] = resp.code
            retval['RAW'] = f"HTTP/1.1 {retval['HTTPCODE']} {resp.reason}\n{str(resp.headers)}\n{retval['HTML']}"
        except Exception as ex:
            #print(f'[x] Get Exception when request {url}.')
            retval['URL'] = getattr(ex, "url", url)
            retval['HTTPCODE'] = getattr(ex, "code", None)
            try:
                retval['HTML'] = ex.read() if hasattr(ex, "read") else str(ex)
            except:
                retval['HTML'] = ""
            retval['RAW'] = f"HTTP/1.1 {retval['HTTPCODE'] or ''} {getattr(ex, 'msg', '')}\n{str(ex.headers) if hasattr(ex, 'headers') else ''}\n{retval['HTML']}"

        for encoding in re.findall(r"charset=[\s\"']?([\w-]+)", retval['RAW'])[::-1] + ["utf-8"]:
            encoding = self.ENCODING_TRANSLATIONS.get(encoding, encoding)
            try:
                retval['HTML'] = retval['HTML'].decode(encoding, errors="replace")
                break
            except:
                pass

        match = re.search(r"<title>\s*(?P<result>[^<]+?)\s*</title>", retval['HTML'], re.I)
        retval['TITLE'] = match.group("result") if match and "result" in match.groupdict() else None
        retval['TEXT'] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ",
                                retval['HTML']).strip()
        match = re.search(r"(?im)^Server: (.+)", retval['RAW'])
        retval['SERVER'] = match.group(1).strip() if match else ""
        return retval

    def format_name(self, waf):
        waf_info = self.DATA_JSON["wafs"].get(waf, {})
        name = waf_info.get("name", "")
        company = waf_info.get("company", "")
        if name != company:
            return "%s (%s)" % (name, company)
        else:
            return name

    def non_blind_check(self, raw, silent=False):
        retval = False
        match = re.search(self.WAF_RECOGNITION_REGEX, raw or "")
        if match:
            retval = True
            for key, value in match.groupdict().items():
                if value:
                    waf = re.sub(r"^waf_", "", key)
                    self.non_blind.add(waf)
                    if not silent:
                        print(f"[+] non-blind match: '{self.format_name(waf)}'{' ' * 20}")
        return retval

    def heuristic_test(self, protection_regex=None):
        if protection_regex is None:
            protection_regex = self.GENERIC_PROTECTION_REGEX % '|'.join(self.GENERIC_PROTECTION_KEYWORDS)
        query_separator = '?' if '?' not in self.url else '&'
        payload_data = f"{self.url}{query_separator}{''.join(random.sample('abcdefghijklmnopqrstuvwxyz', 3))}={quote(self.HEURISTIC_PAYLOAD)}"
        self.intrusive = self.retrieve(payload_data)
        match = re.search(re.sub(r"Server:|Protected by", "".join(random.sample('abcdefghijklmnopqrstuvwxyz', 6)),
                                 self.WAF_RECOGNITION_REGEX, flags=re.I), self.intrusive.get('RAW', ''))
        if match:
            for _ in match.groupdict():
                if match.group(_):
                    waf = re.sub(r"\Awaf_", "", _)
                    print(f'[!] Find waf: {waf}')
                    locked_regex = self.DATA_JSON["wafs"][waf]["regex"]
                    print(f'[!] Find waf regex: {locked_regex}')
                    locked_code = self.intrusive['HTTPCODE']
                    print(f'[!] Intrusive code: {locked_code}')
                    break
        else:
            print("[x] Can't lock results to a non-blind match")

        if not self.intrusive['HTTPCODE']:
            print("[i] rejected summary: RST|DROP")
        else:
            matched_strings = [
                match.group(0) for match in re.finditer(
                    self.GENERIC_ERROR_MESSAGE_REGEX,
                    self.intrusive['HTML']
                )
            ]
            summary = "...".join(matched_strings).strip().replace("  ", " ")
            title_part = f"<title>{self.intrusive['TITLE']}</title>" if self.intrusive['TITLE'] else ""
            error_part = f"...{summary}" if summary and self.intrusive['HTTPCODE'] >= 400 else ""
            message = f"[i] rejected summary: {self.intrusive['HTTPCODE']} ('{title_part}{error_part}')"
            message = message.replace(" ('')", "")
            print(message)
        found = False
        if self.intrusive['HTTPCODE'] is not None:
            found = self.non_blind_check(self.intrusive['RAW'])
        if found is False:
            print("[-] non-blind match: -")

    def detect(self):
        if not self.url.startswith("http"):
            self.url = f"http://{self.url}"
        hostname = urlparse(self.url).hostname
        if hostname and not hostname.replace('.', "").isdigit():
            print(f"[i] checking hostname '{hostname}'...")
            try:
                socket.getaddrinfo(hostname, None)
            except socket.gaierror:
                print(f"[x] host '{hostname}' does not exist")
                exit(1)
        original = self.retrieve(self.url)
        # print(original)

        if 300 <= (original['HTTPCODE'] or 0) < 400 and original['URL']:
            original = self.retrieve(original['URL'])

        if original['HTTPCODE'] is None:
            exit("[x] missing valid response")

        if original['HTTPCODE'] >= 400:
            self.non_blind_check(original['RAW'])

        protection_keywords = self.GENERIC_PROTECTION_KEYWORDS
        protection_regex = f"(?i)\\b({'|'.join(keyword for keyword in protection_keywords if keyword not in original['HTML'].lower())})\\b"

        print("[i] running basic heuristic test...")
        self.heuristic_test(protection_regex)

    def run(self):
        self.detect()
