import json
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def save_results(scan_id, results, output_dir="../scans_output"):
    # Create the directory if it doesn't exist
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{output_dir}/output.json"

    with open(filename, "w") as f:
        json.dump(results, f, indent=2),
    logger.info(f"Saved scan results to {filename}")