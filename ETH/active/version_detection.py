import socket
import re

def detect_service_version(banner, port):
    """
    Detects the service version based on the banner received from the given port.
    """
    if port == 80 or port == 443:  # HTTP/HTTPS
        match = re.search(r"Apache/(\d+\.\d+\.\d+)", banner)
        if match:
            print(f" - Apache Version: {match.group(1)}")
        match = re.search(r"nginx/(\d+\.\d+\.\d+)", banner)
        if match:
            print(f" - Nginx Version: {match.group(1)}")
    elif port == 22:  # SSH
        match = re.search(r"OpenSSH_([0-9.]+)", banner)
        if match:
            print(f" - OpenSSH Version: {match.group(1)}")
    elif port == 21:  # FTP
        match = re.search(r"vsftpd (\d+\.\d+\.\d+)", banner)
        if match:
            print(f" - vsftpd Version: {match.group(1)}")
    elif port == 25:  # SMTP
        match = re.search(r"Postfix (\d+\.\d+\.\d+)", banner)
        if match:
            print(f" - Postfix Version: {match.group(1)}")

def get_banner(target, port, timeout=3):
    """
    Connects to the service on the given port and attempts to retrieve a banner.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)  # Increase timeout here
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()

        if banner:
            print(f"[+] Banner from {target}:{port}:\n{banner}")
            return banner
        else:
            print(f"[-] No banner received from {target}:{port}")
            return None
    except socket.timeout:
        print(f"[-] Error connecting to {target}:{port} - timed out")
        return None
    except Exception as e:
        print(f"[-] Error connecting to {target}:{port} - {str(e)}")
        return None

def parse_ports(ports_input):
    """
    Parses a comma-separated list or a range of ports and returns a list of integers.
    """
    ports = []
    for part in ports_input.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports

def scan_ports(target, ports_input):
    """
    Scans the given ports and attempts version detection on each open port.
    """
    print(f"[+] Scanning ports on {target}...")

    if not ports_input:
        print("[-] Please provide ports to scan.")
        return []

    ports = parse_ports(ports_input)
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f" - Port {port} is OPEN")
                open_ports.append(port)
                banner = get_banner(target, port)
                if banner:
                    detect_service_version(banner, port)
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
    """
    Run the version scan and return open ports with version details.
    """
    open_ports = scan_ports(target, ports_input)
    
    for port in open_ports:
        banner = get_banner(target, port)
        if banner:
            detect_service_version(banner, port)

# Example usage:
# run("example.com", "80,443,22")
