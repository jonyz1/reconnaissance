# import socket

# def get_ip(target):
#     try:
#         ip = socket.gethostbyname(target)
#         print(f"[+] IP address of {target}: {ip}")
#         return ip
#     except socket.gaierror:
#         print(f"[-] Unable to resolve IP address for {target}")
#         return None

# def run(target):
#     get_ip(target)


import dns.resolver

def get_all_ips(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        print(f"[+] IPv4 addresses for {domain}:")
        for ipval in result:
            print(f" - {ipval.to_text()}")
    except Exception as e:
        print(f"[-] Error: {e}")

    try:
        result = dns.resolver.resolve(domain, 'AAAA')
        print(f"[+] IPv6 addresses for {domain}:")
        for ipval in result:
            print(f" - {ipval.to_text()}")
    except:
        pass

def run(target):
    get_all_ips(target)
