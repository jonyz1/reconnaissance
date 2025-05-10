import socket

def parse_ports(ports_input):
    ports = []
    for part in ports_input.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports

def scan_ports(target, ports_input=None):
    print(f"[+] Scanning ports on {target}...")

    if ports_input is None:
        print("[-] Please provide ports to scan.")
        return []

    ports = parse_ports(ports_input)
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
def run(target, ports_input):
    scan_ports(target, ports_input) 