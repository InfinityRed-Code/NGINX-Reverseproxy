"""
Input validation functions
"""
import re
from pathlib import Path


def validate_fqdn(fqdn: str) -> bool:
    """
    Validate Fully Qualified Domain Name

    Args:
        fqdn: Domain name to validate

    Returns:
        True if valid, False otherwise
    """
    # Basic FQDN regex pattern
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, fqdn))


def validate_ip(ip: str) -> bool:
    """
    Validate IPv4 address

    Args:
        ip: IP address to validate

    Returns:
        True if valid IPv4, False otherwise
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False

    # Check if octets are in valid range
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)


def validate_port(port: int) -> bool:
    """
    Validate port number

    Args:
        port: Port number to validate

    Returns:
        True if valid port (1-65535), False otherwise
    """
    return 1 <= port <= 65535


def validate_protocol(protocol: str) -> bool:
    """
    Validate protocol scheme

    Args:
        protocol: Protocol to validate (http or https)

    Returns:
        True if valid, False otherwise
    """
    return protocol.lower() in ['http', 'https']


def validate_config_exists(fqdn: str, conf_dir: Path) -> bool:
    """
    Check if configuration file already exists

    Args:
        fqdn: Domain name
        conf_dir: Configuration directory

    Returns:
        True if config exists, False otherwise
    """
    conf_file = conf_dir / f"{fqdn}.conf"
    return conf_file.exists()
