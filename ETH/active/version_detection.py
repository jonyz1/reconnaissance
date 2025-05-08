import re

def detect_service_version(banner, port):
    if port == 80 or port == 443:  # HTTP/HTTPS
        match = re.search(r"Apache/(\d+\.\d+\.\d+)", banner)
        if match:
            print(f" - Apache Version: {match.group(1)}")
        match = re.search(r"nginx/(\d+\.\d+\.\d+)", banner)
        if match:
            print(f" - Nginx Version: {match.group(1)}")
    if port == 22:  # SSH
        match = re.search(r"OpenSSH_([0-9.]+)", banner)
        if match:
            print(f" - OpenSSH Version: {match.group(1)}")
    if port == 21:  # FTP
        match = re.search(r"vsftpd (\d+\.\d+\.\d+)", banner)
        if match:
            print(f" - vsftpd Version: {match.group(1)}")
    if port == 25:  # SMTP
        match = re.search(r"Postfix (\d+\.\d+\.\d+)", banner)
        if match:
            print(f" - Postfix Version: {match.group(1)}")

def run(target, ports_input):
    # Assuming we are passed open ports from portscan
    # Call version detection logic based on those open ports
    pass
