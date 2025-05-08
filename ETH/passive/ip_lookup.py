import socket

def get_ip(target):
    try:
        ip = socket.gethostbyname(target)
        print(f"[+] IP address of {target}: {ip}")
        return ip
    except socket.gaierror:
        print(f"[-] Unable to resolve IP address for {target}")
        return None

def run(target):
    get_ip(target)
