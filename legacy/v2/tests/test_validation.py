"""
Unit tests for validation module
"""
import pytest
from nrp.core.validation import (
    validate_fqdn,
    validate_ip,
    validate_port,
    validate_protocol
)


class TestValidateFQDN:
    """Tests for FQDN validation"""

    def test_valid_fqdn(self):
        assert validate_fqdn("example.com") is True
        assert validate_fqdn("sub.example.com") is True
        assert validate_fqdn("api.test.example.com") is True

    def test_invalid_fqdn(self):
        assert validate_fqdn("example") is False
        assert validate_fqdn("example.") is False
        assert validate_fqdn("") is False
        assert validate_fqdn("192.168.1.1") is False


class TestValidateIP:
    """Tests for IP address validation"""

    def test_valid_ip(self):
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("172.16.0.1") is True
        assert validate_ip("0.0.0.0") is True
        assert validate_ip("255.255.255.255") is True

    def test_invalid_ip(self):
        assert validate_ip("256.1.1.1") is False
        assert validate_ip("192.168.1") is False
        assert validate_ip("192.168.1.1.1") is False
        assert validate_ip("") is False
        assert validate_ip("example.com") is False


class TestValidatePort:
    """Tests for port validation"""

    def test_valid_port(self):
        assert validate_port(80) is True
        assert validate_port(443) is True
        assert validate_port(8080) is True
        assert validate_port(1) is True
        assert validate_port(65535) is True

    def test_invalid_port(self):
        assert validate_port(0) is False
        assert validate_port(65536) is False
        assert validate_port(-1) is False


class TestValidateProtocol:
    """Tests for protocol validation"""

    def test_valid_protocol(self):
        assert validate_protocol("http") is True
        assert validate_protocol("https") is True
        assert validate_protocol("HTTP") is True
        assert validate_protocol("HTTPS") is True

    def test_invalid_protocol(self):
        assert validate_protocol("ftp") is False
        assert validate_protocol("") is False
        assert validate_protocol("http://") is False
