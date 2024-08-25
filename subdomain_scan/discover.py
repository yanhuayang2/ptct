import asyncio
import random
import dns.asyncresolver
from asyncio import Queue
from async_timeout import timeout
import time
class SubDomainScanner:
    def __init__(self, domain, wordlist_path, output_dir, threads=10, dns_servers=None):
        self.total_subdomains = 0
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.output_dir = output_dir
        self.threads = threads
        self.dns_servers = dns_servers if dns_servers else ['8.8.8.8']
        self.queue = Queue()
        self.found_subs = set()
        self.lock = asyncio.Lock()
        self.resolvers = [dns.asyncresolver.Resolver(configure=False) for _ in range(self.threads)]
        for r in self.resolvers:
            r.lifetime = 6.0
            r.timeout = 10.0

    async def load_sub_names(self):
        with open(self.wordlist_path) as inFile:
            lines = set(line.strip() for line in inFile if line.strip())
        for sub in lines:
            await self.queue.put(sub)
        self.total_subdomains = len(lines)

    async def do_query(self, resolver, cur_domain):
        async with timeout(10.2):
            return await resolver.resolve(cur_domain, 'A')

    async def scan(self, resolver):
        resolver.nameservers = [random.choice(self.dns_servers)]
        empty_counter = 0
        while True:
            try:
                sub = self.queue.get_nowait()
                empty_counter = 0
            except asyncio.queues.QueueEmpty:
                empty_counter += 1
                if empty_counter > 10:
                    break
                await asyncio.sleep(0.1)
                continue

            cur_domain = sub + '.' + self.domain
            try:
                if sub in self.found_subs:
                    continue

                answers = await self.do_query(resolver, cur_domain)
                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.address for answer in answers]))
                    if ips:
                        print(f"[+] Find domain: {cur_domain}\t\t{ips}")
                        with open(f'{self.output_dir}/found_subs.txt', 'a') as f:
                            f.write(f'{cur_domain}\t{ips}\n')

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except dns.resolver.NoNameservers:
                pass
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
                pass
            except Exception as e:
                with open('errors.log', 'a') as errFile:
                    errFile.write(f'[{type(e)}] {e}\n')

    async def run(self):
        start_time = time.time()
        await self.load_sub_names()
        tasks = [self.scan(resolver) for resolver in self.resolvers]
        await asyncio.gather(*tasks)
        end_time = time.time()
        elapsed_time = end_time - start_time

        print(f"\n[+] Scanning completed.")
        print(f"[+] Total subdomains scanned: {self.total_subdomains}")
        print(f"[+] Total subdomains found: {len(self.found_subs)}")
        print(f"[+] Total time taken: {elapsed_time:.6f} seconds")
        print(f"[+] The results are saved in subdomain_scan/subdomain_output/found_subs.txt")
