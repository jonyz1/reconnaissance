# import socket
# import re

# def detect_service_version(banner, port):
#     """
#     Detects the service version based on the banner received from the given port.
#     """
#     if port == 80 or port == 443:  # HTTP/HTTPS
#         match = re.search(r"Apache/(\d+\.\d+\.\d+)", banner)
#         if match:
#             print(f" - Apache Version: {match.group(1)}")
#         match = re.search(r"nginx/(\d+\.\d+\.\d+)", banner)
#         if match:
#             print(f" - Nginx Version: {match.group(1)}")
#     elif port == 22:  # SSH
#         match = re.search(r"OpenSSH_([0-9.]+)", banner)
#         if match:
#             print(f" - OpenSSH Version: {match.group(1)}")
#     elif port == 21:  # FTP
#         match = re.search(r"vsftpd (\d+\.\d+\.\d+)", banner)
#         if match:
#             print(f" - vsftpd Version: {match.group(1)}")
#     elif port == 25:  # SMTP
#         match = re.search(r"Postfix (\d+\.\d+\.\d+)", banner)
#         if match:
#             print(f" - Postfix Version: {match.group(1)}")

# def get_banner(target, port, timeout=3):
#     """
#     Connects to the service on the given port and attempts to retrieve a banner.
#     """
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(timeout)  # Increase timeout here
#         sock.connect((target, port))
#         banner = sock.recv(1024).decode().strip()
#         sock.close()

#         if banner:
#             print(f"[+] Banner from {target}:{port}:\n{banner}")
#             return banner
#         else:
#             print(f"[-] No banner received from {target}:{port}")
#             return None
#     except socket.timeout:
#         print(f"[-] Error connecting to {target}:{port} - timed out")
#         return None
#     except Exception as e:
#         print(f"[-] Error connecting to {target}:{port} - {str(e)}")
#         return None

# def parse_ports(ports_input):
#     """
#     Parses a comma-separated list or a range of ports and returns a list of integers.
#     """
#     ports = []
#     for part in ports_input.split(','):
#         if '-' in part:
#             start, end = part.split('-')
#             ports.extend(range(int(start), int(end) + 1))
#         else:
#             ports.append(int(part))
#     return ports

# def scan_ports(target, ports_input):
#     """
#     Scans the given ports and attempts version detection on each open port.
#     """
#     print(f"[+] Scanning ports on {target}...")

#     if not ports_input:
#         print("[-] Please provide ports to scan.")
#         return []

#     ports = parse_ports(ports_input)
#     open_ports = []

#     for port in ports:
#         try:
#             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             sock.settimeout(1)
#             result = sock.connect_ex((target, port))
#             if result == 0:
#                 print(f" - Port {port} is OPEN")
#                 open_ports.append(port)
#                 banner = get_banner(target, port)
#                 if banner:
#                     detect_service_version(banner, port)
#             sock.close()
#         except KeyboardInterrupt:
#             print("\n[!] Scan interrupted by user.")
#             break
#         except socket.gaierror:
#             print("[!] Hostname could not be resolved.")
#             break
#         except socket.error:
#             print("[!] Could not connect to server.")
#             break

#     if not open_ports:
#         print("[-] No open ports found.")
#     else:
#         print(f"[+] Scan complete. Open ports: {open_ports}")

#     return open_ports

# def run(target, ports_input):
#     """
#     Run the version scan and return open ports with version details.
#     """
#     open_ports = scan_ports(target, ports_input)
    
#     for port in open_ports:
#         banner = get_banner(target, port)
#         if banner:
#             detect_service_version(banner, port)


import socket
import re

def send_protocol_probe(sock, port):
    """
    Sends protocol-specific probes based on the port number.
    """
    try:
        if port in [80, 8080, 443]:  # HTTP/HTTPS
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 25:  # SMTP
            sock.sendall(b"EHLO test.com\r\n")
        elif port == 110:  # POP3
            sock.sendall(b"QUIT\r\n")
        elif port == 143:  # IMAP
            sock.sendall(b"1 CAPABILITY\r\n")
        else:
            sock.sendall(b"Hello\r\n")
    except Exception:
        pass  # In case the protocol doesn’t respond to probes

def detect_service_version(banner, port):
 
    """
    Prints only the service version based on the banner and port.
    """
    if port in [80, 443, 8080]:  # HTTP/HTTPS
        if match := re.search(r"Apache/(\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: Apache {match.group(1)}")
        elif match := re.search(r"nginx/(\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: Nginx {match.group(1)}")
        elif match := re.search(r"LiteSpeed/(\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: LiteSpeed {match.group(1)}")
        elif match := re.search(r"Microsoft-IIS/(\d+\.\d+)", banner):
            print(f"Port {port}: Microsoft-IIS {match.group(1)}")
        elif match := re.search(r"Varnish/(\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: Varnish {match.group(1)}")
        elif match := re.search(r"Squid/(\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: Squid Proxy {match.group(1)}")

    elif port == 22:  # SSH
        if match := re.search(r"OpenSSH[_\- ](\d+\.\d+)", banner):
            print(f"Port {port}: OpenSSH {match.group(1)}")
        elif match := re.search(r"Dropbear sshd v(\d+\.\d+)", banner):
            print(f"Port {port}: Dropbear SSH {match.group(1)}")

    elif port == 21:  # FTP
        if match := re.search(r"vsftpd (\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: vsftpd {match.group(1)}")
        elif match := re.search(r"ProFTPD (\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: ProFTPD {match.group(1)}")
        elif match := re.search(r"Pure-FTPd (\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: Pure-FTPd {match.group(1)}")

    elif port == 25:  # SMTP
        if match := re.search(r"Postfix (\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: Postfix {match.group(1)}")
        elif match := re.search(r"Exim (\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: Exim {match.group(1)}")
        elif match := re.search(r"Sendmail (\d+\.\d+\.\d+)", banner):
            print(f"Port {port}: Sendmail {match.group(1)}")

    elif port == 110:  # POP3
        if match := re.search(r"Dovecot ready \((\d+\.\d+)", banner):
            print(f"Port {port}: Dovecot POP3 {match.group(1)}")
        elif match := re.search(r"Courier-IMAP ready \((\d+\.\d+)", banner):
            print(f"Port {port}: Courier POP3 {match.group(1)}")

    elif port == 143:  # IMAP
        if match := re.search(r"Dovecot ready \((\d+\.\d+)", banner):
            print(f"Port {port}: Dovecot IMAP {match.group(1)}")
        elif match := re.search(r"Courier-IMAP ready \((\d+\.\d+)", banner):
            print(f"Port {port}: Courier IMAP {match.group(1)}")

    elif port == 3306:  # MySQL
        if match := re.search(r"MySQL\s+Server\s+version\s+([\d\.]+)", banner):
            print(f"Port {port}: MySQL {match.group(1)}")
        elif match := re.search(r"5\.\d+\.\d+", banner):
            print(f"Port {port}: MySQL {match.group(0)}")
        elif match := re.search(r"MariaDB\s+([\d\.]+)", banner):
            print(f"Port {port}: MariaDB {match.group(1)}")

    elif port == 5432:  # PostgreSQL
        if match := re.search(r"PostgreSQL\s+([\d\.]+)", banner):
            print(f"Port {port}: PostgreSQL {match.group(1)}")


def get_banner(target, port, timeout=3):
    """
    Grabs a banner from the service using protocol-specific probes.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        send_protocol_probe(sock, port)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner
    except:
        return None

def parse_ports(ports_input):
    """
    Parses ports from a comma-separated or range string.
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
    Scans ports and detects only the service version.
    """
    ports = parse_ports(ports_input)
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                banner = get_banner(target, port)
                if banner:
                    detect_service_version(banner, port)
            sock.close()
        except:
            continue

def run(target, ports_input):
    """
    Entry point to scan and print versions only.
    """
    scan_ports(target, ports_input)
