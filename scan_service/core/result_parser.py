import json
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def save_results(scan_id, results, output_dir="../scans_output"):
    # Create the directory if it doesn't exist
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{output_dir}/output.json"

    if os.path.exists(filename):
        with open(filename, "r") as f:
            existing_data = json.load(f)
    else:
        existing_data = {}
    
    existing_data[scan_id] = results

    with open(filename, "w") as f:
        json.dump(existing_data, f, indent=2),
    logger.info(f"Saved scan results to {filename}")