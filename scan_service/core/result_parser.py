import json
import os
import logging
from pathlib import Path
from threading import Lock # Thread safety
from cve_lookup import CVELookup


logger = logging.getLogger(__name__)
file_lock = Lock()

def save_scan_results(scan_id, results, output_dir="../scans_output"):
    # Create the directory if it doesn't exist
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{output_dir}/output.json"

    try:
        with file_lock: #Thread safe operation
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    existing_data = json.load(f)
            else:
                existing_data = {}
            
            # Append new scan results under scan_id key
            existing_data[scan_id] = results

            # wrtie updated data back to file
            with open(filename, "w") as f:
                json.dump(existing_data, f, indent=2),
            logger.info(f"Saved scan results to {filename}")


    except Exception as e:
        logger.error(f"failed to save scan {scan_id}: {str(e)}")
        raise

def save_cve_results(scan_id, product, version, vendor="", output_dir="../scans_output"):
    cve_lookup = CVELookup()
    cve_data = cve_lookup.search_cves(product, version) # TODO: Add vendor functionality
    filename = f"{output_dir}/output.json"

    try:
        if os.path.exists(filename):
            with open(filename, "r") as f:
                existing_data = json.load(f)
        else:
            existing_data = {}
        
        # Append new scan results under scan_id key
        existing_data[scan_id]["cve_data"] = cve_data

        # wrtie updated data back to file
        with open(filename, "w") as f:
            json.dump(existing_data, f, indent=2),
        logger.info(f"Saved scan results to {filename}")

    except Exception as e:
        raise
        
