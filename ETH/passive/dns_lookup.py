import dns.resolver

def get_dns_servers(target):
    try:
        result = dns.resolver.resolve(target, 'NS')
        print(f"[+] DNS Servers for {target}:")
        for ip in result:
            print(f" - {ip.to_text()}")
    except dns.resolver.NoAnswer:
        print(f"[-] No DNS records found for {target}")

def run(target):
    get_dns_servers(target)
