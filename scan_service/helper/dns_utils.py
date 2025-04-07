import socket
import logging

logger = logging.getLogger(__name__)

def resolve_domain(target):
    """
    resolve a domain name to an IP address

    Args:
        target (str): Domain name (e.g. "example.com")
    
    Returns: 
        str: Resolved IP address or None if resolution failed
    """

    try:
        ip = socket.gethostbyname(target)
        logger.info(f"Resolved {target} to {ip}")
        return ip
    except socket.gaierror:
        logger.warning(f"Could not resolve {target}. ensure it's a valid domain")
        return None
    