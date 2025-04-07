import json
import os
import logging
from pathlib import Path
from threading import Lock # Thread safety

logger = logging.getLogger(__name__)
file_lock = Lock()

def save_results(scan_id, results, output_dir="../scans_output"):
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