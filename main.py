#!/usr/bin/env python3
import argparse
import json
import sys
from colorama import init, Fore, Style
from header_hound.scanner import HeaderScanner

def print_banner():
    """Prints a styled ASCII banner."""
    banner = f"""{Fore.CYAN}
  _    _                _             _    _                       _ 
 | |  | |              | |           | |  | |                     | |
 | |__| | ___  __ _  __| | ___ _ __  | |__| | ___  _   _ _ __   __| |
 |  __  |/ _ \/ _` |/ _` |/ _ \ '__| |  __  |/ _ \| | | | '_ \ / _` |
 | |  | |  __/ (_| | (_| |  __/ |    | |  | | (_) | |_| | | | | (_| |
 |_|  |_|\___|\__,_|\__,_|\___|_|    |_|  |_|\___/ \__,_|_| |_|\__,_|
                                                                     
    Security Header Analyzer - Identify misconfigurations instantly
    {Style.RESET_ALL}"""
    print(banner)

def main():
    # Initialize colorama for cross-platform color support
    init(autoreset=True)
    
    parser = argparse.ArgumentParser(description="Analyze HTTP response headers for security misconfigurations.")
    parser.add_argument("url", help="Target URL to scan (e.g., example.com)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification (useful for internal/dev sites)")
    parser.add_argument("--json", dest="export_json", help="Export results to a specified JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (shows values for passed checks)")
    
    args = parser.parse_args()
    
    print_banner()
    print(f"[*] Target: {Fore.YELLOW}{args.url}{Style.RESET_ALL}")
    print("[*] Fetching headers...")
    
    scanner = HeaderScanner(args.url, verify_ssl=not args.no_verify)
    success, status_or_error = scanner.fetch_headers()
    
    if not success:
        print(f"\n{Fore.RED}[!] Connection Error:{Style.RESET_ALL} {status_or_error}")
        sys.exit(1)
        
    print(f"[*] Response Status: {Fore.GREEN}{status_or_error}{Style.RESET_ALL}")
    print("[*] Analyzing headers...\n")
    
    results = scanner.analyze()
    
    # --- Display Results ---
    
    print(f"{Fore.GREEN}=== PASSED ({len(results['passed'])}) ==={Style.RESET_ALL}")
    for item in results['passed']:
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {item['header']}")
        if args.verbose:
            print(f"    Value: {item['value']}")
            
    print(f"\n{Fore.RED}=== FAILED ({len(results['failed'])}) ==={Style.RESET_ALL}")
    for item in results['failed']:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} {item['header']}: {item['issue']}")
        print(f"    {Fore.CYAN}Fix:{Style.RESET_ALL} {item['recommendation']}")
        
    if results['warnings']:
        print(f"\n{Fore.YELLOW}=== WARNINGS ({len(results['warnings'])}) ==={Style.RESET_ALL}")
        for item in results['warnings']:
            print(f"  {Fore.YELLOW}!{Style.RESET_ALL} {item['header']}: {item['issue']}")
            print(f"    {Fore.CYAN}Fix:{Style.RESET_ALL} {item['recommendation']}")

    # --- Export Logic ---
    
    if args.export_json:
        try:
            with open(args.export_json, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"\n[*] Results successfully exported to {Fore.CYAN}{args.export_json}{Style.RESET_ALL}")
        except IOError as e:
            print(f"\n{Fore.RED}[!] Failed to export JSON:{Style.RESET_ALL} {e}")

if __name__ == "__main__":
    main()
