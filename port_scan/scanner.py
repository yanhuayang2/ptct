import asyncio
from urllib.parse import urlparse

class PortScanner:
    def __init__(self, target, ports=None):
        self.target = self.extract_hostname(target)
        self.ports = self.parse_ports(ports)
        self.results = []

    def extract_hostname(self, url):
        parsed_url = urlparse(url)
        return parsed_url.hostname or parsed_url.path

    def parse_ports(self, ports):
        if not ports:
            return range(1, 65535)
        port_list = []
        port_parts = ports.split(',')
        for part in port_parts:
            if '-' in part:
                start, end = part.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
        return port_list

    async def scan_port_async(self, port):
        try:
            conn = asyncio.open_connection(self.target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=3)
            self.results.append((port, 'open'))
            writer.close()
            await writer.wait_closed()
        except asyncio.TimeoutError:
            # print(f"Connect {port} TimeoutError.")
            self.results.append((port, 'closed'))
        except ConnectionRefusedError:
            # print(f"Connect {port} ConnectionRefusedError.")
            self.results.append((port, 'closed'))
        except Exception as e:
            print(f"Unexpected error: {e}")
            self.results.append((port, 'closed'))

    async def scan_ports_async(self):
        tasks = [self.scan_port_async(port) for port in self.ports]
        await asyncio.gather(*tasks)

    def run(self):
        print(f"[i] Scanning port of {self.target}")
        asyncio.run(self.scan_ports_async())
        return self.results
