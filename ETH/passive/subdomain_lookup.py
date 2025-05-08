import requests
from requests.exceptions import ConnectionError, Timeout, HTTPError

def find_subdomains(target):
    url = f"https://api.sublist3r.com/search.php?domain={target}"

    try:
        response = requests.get(url)
        response.raise_for_status()  # Check if the request was successful (HTTP 200)
        subdomains = response.json()
        if subdomains:
            print(f"[+] Found subdomains for {target}:")
            for subdomain in subdomains:
                print(f" - {subdomain}")
        else:
            print(f"[-] No subdomains found for {target}.")
    except ConnectionError:
        print("[-] Connection error. Could not reach the subdomain lookup service.")
    except Timeout:
        print("[-] The request timed out. Please try again later.")
    except HTTPError as e:
        print(f"[-] HTTP error occurred: {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

def run(target):
    find_subdomains(target)
