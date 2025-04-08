import sys
import os
import time
import queue
import threading
from scanner.xss_scanner import XSSScanner

def print_log_messages(log_queue):
    """Print messages from the log queue"""
    while True:
        try:
            message = log_queue.get(block=False)
            print(message)
        except queue.Empty:
            break

def main():
    """Test the Selenium XSS scanning functionality"""
    print("XSS Scanner with Selenium Test")
    print("==============================")
    
    # Create a scanner instance
    scanner = XSSScanner()
    
    # Create a log queue for capturing messages
    log_queue = queue.Queue()
    
    # Ask for the target URL
    target_url = input("Enter the target URL to scan: ")
    
    # Ask if authentication is needed
    auth_needed = input("Do you need authentication? (y/n): ").lower() == 'y'
    
    username = ""
    password = ""
    if auth_needed:
        username = input("Enter username: ")
        password = input("Enter password: ")

    # Ask if the user wants to use selenium
    use_selenium = input("Use Selenium for dynamic testing? (y/n): ").lower() == 'y'
    
    # Set scan parameters
    max_urls = int(input("Maximum number of URLs to scan (default: 10): ") or "10")
    
    print("\nStarting scan. This may take a while...\n")
    
    # Create a thread to run the scan
    if auth_needed:
        scan_thread = threading.Thread(
            target=scanner.scan_with_auth,
            args=(target_url, username, password, max_urls, log_queue, use_selenium)
        )
    else:
        scan_thread = threading.Thread(
            target=scanner.deep_scan,
            args=(target_url, max_urls, log_queue, use_selenium)
        )
    
    scan_thread.start()
    
    # Print log messages while scanning
    try:
        while scan_thread.is_alive():
            print_log_messages(log_queue)
            time.sleep(1)
        
        # Get any remaining messages
        print_log_messages(log_queue)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        # Close Selenium if it was used
        if scanner.use_selenium:
            scanner.close_selenium()
        return
    
    # Get the scan results
    vulnerabilities = scanner.vulnerable_urls
    
    # Print the results
    print("\nScan Results:")
    print("=============")
    
    if vulnerabilities:
        print(f"Found {len(vulnerabilities)} potential vulnerabilities:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n[{i}] URL: {vuln.get('url', 'N/A')}")
            print(f"Type: {vuln.get('type', 'N/A')}")
            
            if 'vector' in vuln:
                print(f"Vector: {vuln['vector']}")
            
            if 'payload' in vuln:
                print(f"Payload: {vuln['payload']}")
            
            if 'details' in vuln:
                if isinstance(vuln['details'], dict):
                    for key, value in vuln['details'].items():
                        print(f"{key}: {value}")
                else:
                    print(f"Details: {vuln['details']}")
    else:
        print("No vulnerabilities found!")
    
    print("\nTest completed.")

if __name__ == "__main__":
    main() 