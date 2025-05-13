import socket
import asyncio
from scapy.all import IP, TCP, UDP, sr1

def parse_ports(ports_input):
    ports = []
    for part in ports_input.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports

def socket_scan_ports(target, ports=None):
    # print(f"[+] Scanning ports on {target}...")

    # if ports is None:
    #     print("[-] Please provide ports to scan.")
    #     return []

    # ports = parse_ports(ports_input)
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f" - Port {port} is OPEN")
                open_ports.append(port)
            sock.close()
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
            break
        except socket.gaierror:
            print("[!] Hostname could not be resolved.")
            break
        except socket.error:
            print("[!] Could not connect to server.")
            break

    if not open_ports:
        print("[-] No open ports found.")
    else:
        print(f"[+] Scan complete. Open ports: {open_ports}")

    return open_ports

async def async_scan_port(target, port):
    try:
        reader, writer = await asyncio.open_connection(target, port)
        print(f"[+] Port {port} is OPEN")
        writer.close()
        await writer.wait_closed()
    except:
        pass
    
async def asyncio_tcp_scan(target, ports):
    print("[*] Using asyncio TCP scanner...")
    tasks = [async_scan_port(target, port) for port in ports]
    await asyncio.gather(*tasks)
    

def scapy_scan_tcp(target, ports):
    print("[*] Performing TCP connect scan with Scapy...")
    for port in ports:
        pkt = IP(dst=target)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 18:
            print(f"[+] Port {port} is OPEN")

def scapy_scan_syn(target, ports):
    print("[*] Performing SYN scan with Scapy...")
    for port in ports:
        pkt = IP(dst=target)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 18:
            print(f"[+] Port {port} is OPEN")

def scapy_scan_udp(target, ports):
    print("[*] Performing UDP scan with Scapy...")
    for port in ports:
        pkt = IP(dst=target)/UDP(dport=port)
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp is None:
            print(f"[+] Port {port} might be OPEN or FILTERED")
        elif resp.haslayer(UDP):
            print(f"[+] Port {port} is OPEN")
        else:
            print(f"[-] Port {port} is CLOSED")

def scan_ports(target, ports_input, method='auto'):
    ports = parse_ports(ports_input)

    if method == 'auto':
        if len(ports) <= 30:
            socket_scan_ports(target, ports)
        else:
            asyncio.run(asyncio_tcp_scan(target, ports))

    elif method == 'tcp':
        scapy_scan_tcp(target, ports)
    elif method == 'syn':
        scapy_scan_syn(target, ports)
    elif method == 'udp':
        scapy_scan_udp(target, ports)
    else:
        print("[-] Unknown method. Use one of: auto, tcp, syn, udp.")

def run(target, ports_input,method):
   scan_ports(target, ports_input,method) 