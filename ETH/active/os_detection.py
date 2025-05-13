from scapy.all import IP, TCP, UDP, sr1
import socket

def os_detection(banner):
    if banner:
        banner = banner.decode(errors="ignore")
        if "Linux" in banner:
            print(f"[+] Operating System: Likely Linux")
        elif "Windows" in banner:
            print(f"[+] Operating System: Likely Windows")
        elif "Unix" in banner:
            print(f"[+] Operating System: Likely Unix")
        elif "Debian" in banner or "Ubuntu" in banner:
            print(f"[+] Operating System: Likely a Debian-based Linux distro")
        elif "CentOS" in banner or "Red Hat" in banner:
            print(f"[+] Operating System: Likely a RedHat-based Linux distro")
        else:
            print(f"[?] Could not determine OS from banner: {banner.strip()}")
    else:
        print("[-] No banner received.")

def scapy_fingerprint(target, port=80):
    ip = IP(dst=target)
    syn = TCP(dport=port, flags="S")
    resp = sr1(ip/syn, timeout=2, verbose=0)

    if not resp:
        print("[-] No response.")
        return

    # Extract TTL and window size
    ttl = resp.ttl
    window = resp[TCP].window
    flags = resp.sprintf("%TCP.flags%")
    
    print(f"[+] TTL: {ttl}, Window Size: {window}, Flags: {flags}")

    # Very simple heuristic
    if ttl >= 128 and window in [8192, 64240]:
        print("[+] Likely OS: Windows")
    elif ttl >= 64 and window in [5840, 14600]:
        print("[+] Likely OS: Linux")
    elif ttl >= 255:
        print("[+] Likely OS: Network device or BSD variant")
    else:
        print("[?] Unknown OS")

def run(target, ports_input):
    from active.portscan import parse_ports

    ports = parse_ports(ports_input)
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target, port))
            sock.send(b"Hello\r\n")  # Try to trigger a response
            banner = sock.recv(1024)
            print(f"[+] Port {port} banner:")
            os_detection(banner)
            sock.close()
        except socket.timeout:
            print(f"[-] Port {port} timed out.")
        except Exception as e:
            print(f"[-] Error on port {port}: {e}")
    # scapy_fingerprint(target, port=80)
