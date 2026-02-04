#!/usr/bin/env python3
# My Simple Port Scanner Project
# For university / placement portfolio
# Learning how to use python-nmap

import argparse
import sys
import nmap
from datetime import datetime

# Some colors to make output look nicer
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
RESET   = "\033[0m"

def print_header():
    print(f"{BLUE}=== My Simple Scanner v0.7 ==={RESET}")
    print(f"{YELLOW}WARNING !!!{RESET}")
    print("Only scan computers YOU own or have clear permission to scan!")
    print("Scanning without permission is illegal.\n")

def get_arguments():
    parser = argparse.ArgumentParser(description="Simple port scanner I made myself")
    parser.add_argument("target", help="IP or hostname to scan (example: 192.168.1.1)")
    parser.add_argument("-p", "--ports", default="1-1000",
                        help="Which ports to scan (default: 1-1000)")
    parser.add_argument("-o", "--output",
                        help="Save results to this file (example: -o results.txt)")
    return parser.parse_args()

def run_nmap_scan(target, ports):
    nm = nmap.PortScanner()
    print(f"{GREEN}[*] Scanning {target} ... please wait ...{RESET}")
    
    # Basic scan with version detection
    scan_options = "-sV -T3"
    if ports != "1-1000":
        scan_options += f" -p {ports}"
    
    try:
        nm.scan(target, arguments=scan_options)
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
        print("Maybe the target is down or you need sudo?")
        sys.exit(1)
    
    return nm

def print_scan_results(nm, target):
    if len(nm.all_hosts()) == 0:
        print(f"{RED}[-] No response from {target} (maybe down or blocked){RESET}")
        return
    
    # We usually get only one host
    host_ip = nm.all_hosts()[0]
    host = nm[host_ip]
    
    hostname = host.hostname()
    if not hostname:
        hostname = "no hostname"
    
    print(f"\n{GREEN}[+] Target: {host_ip} ({hostname}) - Status: {host.state()}{RESET}")
    
    # Show open ports in a nice table
    print("\nOpen Ports:")
    print("-" * 70)
    print(f"{'Port':<10} {'Service':<15} {'Version / Info':<40}")
    print("-" * 70)
    
    found_open = False
    for proto in host.all_protocols():
        ports = host[proto].keys()
        for port in sorted(ports):
            if host[proto][port]['state'] == 'open':
                found_open = True
                info = host[proto][port]
                service_name = info.get('name', 'unknown')
                version = info.get('version', '')
                product = info.get('product', '')
                extra = info.get('extrainfo', '')
                
                version_info = f"{product} {version}".strip()
                if extra:
                    version_info += f" ({extra})"
                
                # Simple warning messages
                comment = ""
                if "Apache" in product and "2.4.7" in version:
                    comment = f" {RED}← old version - possible vulnerabilities{RESET}"
                elif service_name == "ftp" and "anonymous" in extra.lower():
                    comment = f" {RED}← anonymous login allowed!{RESET}"
                elif "OpenSSH" in product and any(x in version for x in ["5.", "6.", "7.0"]):
                    comment = f" {YELLOW}← quite old version{RESET}"
                
                print(f"{port:<10} {service_name:<15} {version_info:<40}{comment}")
    
    if not found_open:
        print("No open ports found in the scanned range.")

def save_to_file(nm, filename, target):
    if not filename:
        return
    
    try:
        with open(filename, "w") as f:
            f.write(f"Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {target}\n")
            f.write(f"Command: {nm.command_line()}\n")
            f.write("=" * 60 + "\n\n")
            
            # Save the same table format as we printed
            f.write("Open Ports:\n")
            f.write("-" * 70 + "\n")
            f.write(f"{'Port':<10} {'Service':<15} {'Version / Info':<40}\n")
            f.write("-" * 70 + "\n")
            
            host_ip = nm.all_hosts()[0]
            host = nm[host_ip]
            
            for proto in host.all_protocols():
                for port in sorted(host[proto]):
                    if host[proto][port]['state'] == 'open':
                        info = host[proto][port]
                        service = info.get('name', 'unknown')
                        version = info.get('version', '')
                        product = info.get('product', '')
                        extra = info.get('extrainfo', '')
                        
                        line = f"{port:<10} {service:<15} {product} {version}"
                        if extra:
                            line += f" ({extra})"
                        f.write(line + "\n")
            
            f.write("\nRaw Nmap output:\n")
            f.write("-" * 60 + "\n")
            raw = nm.get_nmap_last_output()
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            f.write(raw)
        
        print(f"{GREEN}[+] Results saved to: {filename}{RESET}")
    
    except Exception as e:
        print(f"{RED}Could not save file: {e}{RESET}")

def main():
    print_header()
    args = get_arguments()
    
    nm = run_nmap_scan(args.target, args.ports)
    print_scan_results(nm, args.target)
    save_to_file(nm, args.output, args.target)
    
    if not args.output:
        print(f"\n{YELLOW}Want to save? Use -o filename.txt next time{RESET}")

if __name__ == "__main__":
    main()
