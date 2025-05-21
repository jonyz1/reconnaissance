import sys
from active import portscan, version_detection, os_detection
from passive import ip_lookup, subdomain_lookup, dns_lookup
from Vulnerability_identification import vuln_scanner


def show_help():
    print("""
Usage: python check.py <target> <mode> <option> [ports]

Modes:
  active        Perform active reconnaissance (e.g., port scanning, version detection, OS detection).
  passive       Perform passive reconnaissance (e.g., IP lookup, subdomain discovery, DNS lookup).
  vuln          Perform passive Vulnerability identification.

Active Options (for 'active' mode):
  portscan auto         Scan for open ports on the target.
  portscan tcp/udp/syn  Scan with scapy
  version               Detect versions of services running on open ports.
  os                    Detect the operating system based on banners.
  all                   Run portscan, version detection, and OS detection.

Passive Options (for 'passive' mode):
  ip            Lookup the IP address of the target.
  subdomain     Discover subdomains of the target.
  dns           Lookup the DNS servers for the target.
  all           Run IP lookup, subdomain discovery, and DNS lookup.

Example Commands:
  python check.py example.com active portscan 80,443,22
  python check.py example.com passive subdomain
  python check.py 8.8.8.8 passive dns
  python check.py example.com active all 1-100

Note: Ports can be provided as a comma-separated list (e.g., 80,443,22) or as a range (e.g., 1-100).
""")

def run_active(target, option, ports_input,method):
    if option == 'portscan':
        portscan.run(target, ports_input,method)
    elif option == 'version':
        version_detection.run(target, ports_input)
    elif option == 'os':
        os_detection.run(target, ports_input)
    elif option == 'all':
        portscan.run(target, ports_input,method)
        version_detection.run(target, ports_input)
        os_detection.run(target, ports_input)
    else:
        print("[-] Invalid active option.")

def run_passive(target, option):
    if option == 'ip':
        ip_lookup.run(target)
    elif option == 'subdomain':
        subdomain_lookup.run(target)
    elif option == 'dns':
        dns_lookup.run(target)
    elif option == 'all':
        ip_lookup.run(target)
        subdomain_lookup.run(target)
        dns_lookup.run(target)
    else:
        print("[-] Invalid passive option.")

if __name__ == "__main__":
    if len(sys.argv) <= 3:
        print("[-] Please specify a target, mode, and option. Use 'help' for assistance.")
        sys.exit(1)

    if sys.argv[1] == 'help':
        show_help()
        sys.exit(0)

    if len(sys.argv) > 6:
        print("Usage: python check.py <target> <mode> <option> [ports] [method]")
        sys.exit(1)

    target = sys.argv[1]
    mode = sys.argv[2]
    if mode=="vuln":
        pass  
    else:
        option = sys.argv[3]
        method="None"
        if mode=="active":
            if option=="portscan":
                method = sys.argv[5] if len(sys.argv) == 6 else "none"
                if method == "None":
                    print("Usage: python check.py <target> <mode> <option> [ports] [method]")
                    sys.exit(1)
            ports_input = sys.argv[4] if len(sys.argv) ==5  else "None"
            if ports_input == "None":
                print("Include Ports at the end")
                sys.exit(1)
            


    if mode == 'active':
        run_active(target, option, ports_input,method)
    elif mode == 'passive':
        run_passive(target, option)
    elif mode =='vuln':
        vuln_scanner.run(target)
    else:
        print("[-] Invalid mode. Use 'active' or 'passive'.")
