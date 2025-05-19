import nmap
import uuid
import datetime
import logging
import result_parser
from cve_lookup import CVELookup

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, config):
        self.scanner = nmap.PortScanner()
        self.config = config

    # This function prevents invalid inputs from crashing the tool or causing security issues
    # Could lead to command injections
    def _is_valid_target(self, target):
        import re
        return re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target) is not None

    
    def scan(self, target, scan_type="basic", argument="-sV"):
        """
        Execute a network scan against the target
        
        Parameters:
        - target: IP address, hostname, or CIDR notation
        - scan_type: Type of scan (basic, comprehensive, service, etc.)
        
        Returns:
        - scan_id: Unique identifier for this scan
        - scan_results: Raw scan results
        """

        # Validate target format (IP/CIDR/Hostname)
        if not self._is_valid_target(target):
            raise ValueError(f"Invalid target format: {target}")
        
        # TODO: Domain resolution
        
        # Validate scan_type
        valid_types = ["basic", "comprehensive", "service", "custom", "udp"]
        if scan_type not in valid_types:
            raise ValueError(f"Invalid scan type. Choose from: {valid_types}")

        scan_id = str(uuid.uuid4())
        logger.info(f"Starting scan {scan_id} on target {target}")


        """
        Some scans will require root privilege, which requires the scanner_demo.py file
        to be rum with sudo
        """
        try:
            #Select scan argyument based on scan type
            if scan_type == "basic":
                args = "-sV -F --open" # version detection, fast scan, only show open ports
            elif scan_type == "comprehensive":
                args = "-sS -sV -sC -O -p- --open" #SYN scan, service detection, scripts, OS detection, all ports
            elif scan_type == "service":
                args = "-sV --version-intensity 7" # Intensive service version detection
            elif scan_type == "udp":
                args = "-sU -sV --open" #UDP scan with service detection, UDP can be exploited by attackers E.g. DNS amplification
            elif scan_type == "custom":
                args = argument
            else:
                args = "-sV"

            start_time = datetime.datetime.now()

            # Execute the scan
            self.scanner.scan(target, arguments=args)
            
            end_time = datetime.datetime.now()

            duration = (end_time - start_time).total_seconds()

            # Extract the results
            results = {
                scan_id: {
                    "target": target,
                    "scan_type": scan_type,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "duration": duration,
                    # "raw_results": self.scanner.get_nmap_last_output(),
                    "hosts": {}
                }
            }

            # Parse namp output into structured formate
            for host in self.scanner.all_hosts():
                results[scan_id]["hosts"][host] = {
                    "status": self.scanner[host].state(),
                    "hostnames": self.scanner[host].hostnames(),
                    "ports": {}
                }

                # Add OS information if available
                if hasattr(self.scanner[host], 'osclass') and self.scanner[host].osclass():
                    results[scan_id]["hosts"][host]["os"] = self.scanner[host].osclass()

                # Add port and service information
                for proto in self.scanner[host].all_protocols():
                    results[scan_id]["hosts"][host]["ports"][proto] = {}

                    for port in self.scanner[host][proto].keys():
                        port_info = self.scanner[host][proto][port]
                        results[scan_id]["hosts"][host]["ports"][proto][port] = port_info
                
                # Adding placeholders for future vulnerability data and behaviours
                results[scan_id]["cve_data"] = {}

            logger.info(f"Completed Scan {scan_id}, duration: {end_time-start_time}")

            # Saving the results in json file using results parser
            result_parser.save_scan_results(scan_id, results)
            result_parser.save_cve_results(scan_id, )
            return scan_id, results
    
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {str(e)}")
            return scan_id, {"error": str(e), "scan_id": scan_id, "target": target}
