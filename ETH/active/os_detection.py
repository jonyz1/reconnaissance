def os_detection(banner):
    if banner:
        if "Linux" in banner:
            print(f"[+] Operating System: Likely Linux")
        elif "Windows" in banner:
            print(f"[+] Operating System: Likely Windows")
        else:
            print(f"[-] Could not determine OS from banner")

def run(target, ports_input):
    # Assuming we are passed open ports and banners from portscan
    pass
