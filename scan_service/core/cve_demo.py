# test_scanner.py
import logging
from cve_lookup import CVELookup

# Configure logging to see detailed output
logging.basicConfig(level=logging.INFO)

def main():
    # Initialize the scanner with an empty config (adjust if needed)
    cve_lookup = CVELookup()

    cve_lookup.search_cves("Apache httpd", "2.4.7")

if __name__ == "__main__":
    main()