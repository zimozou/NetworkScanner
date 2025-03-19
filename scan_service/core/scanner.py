import nmap
import uuid
import datetime
import logging

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, config):
        self.scanner = nmap.PortScanner()
        self.config = config
    
    def scan(self, target, scan_type="basic"):
        """
        Execute a network scan against the target
        
        Parameters:
        - target: IP address, hostname, or CIDR notation
        - scan_type: Type of scan (basic, comprehensive, service, etc.)
        
        Returns:
        - scan_id: Unique identifier for this scan
        - scan_results: Raw scan results
        """

        scan_id = str(uuid.uuid4())
        logger.info(f"Starting scan {scan_id} on target {target}")

        try:
            #Select scan argyument based on scan type
            if scan_type == "basic":
                args = "-sV -F --open" # version detection, fast scan, only show open ports
            elif scan_type == "comprehensive":
                args = "-sS -sV -sC -O -p- --open" #SYN scan, service detection, scripts, OS detection, all ports
            elif scan_type == "service":
                args = "-sV --version-intersity 7" # Intensive service version detection
            else:
                args = "-sV"

            start_time = datetime.datetime.now()

            # Execute the scan
            self.scanner.scan(target, arguments=args)
            
            end_time = datetime.datetime.now()

            duration = (end_time - start_time).total_seconds()

            # Extract the results
            results = {
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration": duration,
                "raw_results": self.scanner.get_nmap_last_output(),
                "hosts": {}
            }

            # Parse namp output into structured formate
            for host in self.scanner.all_hosts():
                results["hosts"][host] = {
                    "statuss": self.scanner[host].state(),
                    "hostnames": self.scanner[host].hostnames(),
                    "ports": {}
                }

                # Add OS information if available
                if hasattr(self.scanner[host], 'osclass') and self.scanner[host].osclss():
                    results["hosts"][host]["os"] = self.scanner[host].osclass()

                # Add port and service information
                for proto in self.scanner[host].all_protocols():
                    results["hosts"][host]["ports"][proto] = {}

                    for port in self.scanner[host][proto].keys():
                        port_info = self.scanner[host][proto][port]
                        results["hosts"][host]["ports"][proto][port] = port_info

            logger.info(f"Completed Scan {scan_id}, found {sum(len(host_data['ports'].get('tcp', {})) for host_data in results["hosts"].values())} open ports")
            return scan_id, results
    
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {str(e)}")
            return scan_id, {"error": str(e), "scan_id": scan_id, "target": target}
