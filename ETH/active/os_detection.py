# def os_detection(banner):
#     if banner:
#         if "Linux" in banner:
#             print(f"[+] Operating System: Likely Linux")
#         elif "Windows" in banner:
#             print(f"[+] Operating System: Likely Windows")
#         else:
#             print(f"[-] Could not determine OS from banner")

# def run(target, ports_input):
#     # Assuming we are passed open ports and banners from portscan
#     pass
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
