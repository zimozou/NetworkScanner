# test_scanner.py
import logging
from scanner import NetworkScanner  # Replace with your actual module name

# Configure logging to see detailed output
logging.basicConfig(level=logging.INFO)

def main():
    # Initialize the scanner with an empty config (adjust if needed)
    scanner = NetworkScanner(config={})

    # Test parameters
    target = "sasdaw"  # Localhost for safe testing
    scan_type = "basic"   # Start with a quick scan
    # argument = "-sV"

    # Run the scan
    scan_id, results = scanner.scan(target, scan_type)

    # Print basic info
    print(f"Scan ID: {scan_id}")
    print(f"Target: {results.get('target')}")
    print(f"Scan Type: {results.get('scan_type')}")
    
    if 'error' in results:
        print(f"Error: {results['error']}")
        return

    # Print host details
    for host, host_info in results["hosts"].items():
        print(f"\nHost: {host}")
        print(f"Status: {host_info.get('status')}")  # Fixed key name
        if 'os' in host_info:
            print(f"OS Guess: {host_info['os']}")

        # Print port details
        for proto, ports in host_info["ports"].items():
            print(f"\nProtocol: {proto}")
            for port, info in ports.items():
                print(f"  Port {port}: {info.get('name')} ({info.get('state')})")
                print(f"  Service: {info.get('product', 'Unknown')} {info.get('version', '')}")

if __name__ == "__main__":
    main()