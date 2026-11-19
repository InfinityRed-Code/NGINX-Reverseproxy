"""
Certbot/LetsEncrypt operations
"""
import subprocess
from typing import Optional


class CertbotManager:
    """Manages LetsEncrypt certificate operations"""

    def request_certificate(self, fqdn: str, email: Optional[str] = None) -> bool:
        """
        Request SSL certificate for domain

        Args:
            fqdn: Fully qualified domain name
            email: Email for certificate notifications (optional)

        Returns:
            True if successful, False otherwise
        """
        cmd = ["certbot", "--nginx", "-d", fqdn, "--non-interactive"]

        if email:
            cmd.extend(["--email", email, "--agree-tos"])
        else:
            cmd.append("--register-unsafely-without-email")
            cmd.append("--agree-tos")

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True
            )
            print(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error requesting certificate:\n{e.stderr}")
            return False

    def revoke_certificate(self, fqdn: str) -> bool:
        """
        Revoke SSL certificate for domain

        Args:
            fqdn: Fully qualified domain name

        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ["certbot", "revoke", "--cert-name", fqdn, "--non-interactive"],
                check=True,
                capture_output=True,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error revoking certificate: {e.stderr}")
            return False

    def delete_certificate(self, fqdn: str) -> bool:
        """
        Delete SSL certificate for domain

        Args:
            fqdn: Fully qualified domain name

        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ["certbot", "delete", "--cert-name", fqdn, "--non-interactive"],
                check=True,
                capture_output=True,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error deleting certificate: {e.stderr}")
            return False

    def list_certificates(self) -> list[str]:
        """
        List all certificates

        Returns:
            List of certificate names
        """
        try:
            result = subprocess.run(
                ["certbot", "certificates"],
                check=True,
                capture_output=True,
                text=True
            )
            # Parse output to extract certificate names
            # This is a simple implementation, could be improved
            certs = []
            for line in result.stdout.split('\n'):
                if 'Certificate Name:' in line:
                    cert_name = line.split('Certificate Name:')[1].strip()
                    certs.append(cert_name)
            return certs
        except subprocess.CalledProcessError:
            return []

    def renew_certificates(self) -> bool:
        """
        Renew all certificates

        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ["certbot", "renew"],
                check=True,
                capture_output=True,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error renewing certificates: {e.stderr}")
            return False
