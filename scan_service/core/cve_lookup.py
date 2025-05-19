import requests
import time
import logging
from urllib.parse import quote

logger = logging.getLogger(__name__)

class CVELookup:
    def __init__(self, delay=6):
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.delay = delay
    
    def search_cves(self, product, version, vendor=""):
        # Search CVEs for a specific vender or version using the NVD api
        query = f"{product} {version}"
        
        if vendor:
            query = f"{vendor} {query}"

        try:
            time.sleep(self.delay) # Avoid rate limiting

            response = requests.get(
                f"{self.nvd_api}?keywordSearch={query}"
            )
            response.raise_for_status()
            data = response.json()

            for i in data.get("vulnerabilities"):
                print(i)

            return data.get("vulnerabilities")

            # cves = [
            # ]

            # for item in data.get("result", {}).get("CVE_Items", []):
            #     cve_id = item["cve"]["CVE_data_meta"]["ID"]
            #     cvss_score = tiem["impact"].get(baseMetricV3, {}).get
        
        except Exception as e:
            logger.error(f"CVE looup failed for {product} {version}: {str(e)}")
            return {}