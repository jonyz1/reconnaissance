import requests
from requests.exceptions import ConnectionError, Timeout, HTTPError
import json
import re

def get_crtsh_subdomains(target):
    print("[*] Fetching from crt.sh...")
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            # crt.sh sometimes returns multiple domains per cert entry
            for sub in name.splitlines():
                if sub.endswith(target):
                    subdomains.add(sub.strip())
        return list(subdomains)
    except Exception as e:
        print(f"[-] crt.sh error: {e}")
        return []

def find_subdomains(target):
    subdomains = set()

    # subdomains.update(get_sublist3r_subdomains(target))
    subdomains.update(get_crtsh_subdomains(target))

    if subdomains:
        print(f"\n[+] Found {len(subdomains)} unique subdomains for {target}:")
        for sub in sorted(subdomains):
            print(f" - {sub}")
    else:
        print(f"[-] No subdomains found for {target}.")

def run(target):
    find_subdomains(target)

