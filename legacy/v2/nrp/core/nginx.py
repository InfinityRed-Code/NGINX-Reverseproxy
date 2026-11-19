"""
NGINX operations and management
"""
import subprocess
from pathlib import Path
from typing import Optional
from jinja2 import Environment, FileSystemLoader

from nrp.config import (
    NGINX_CONF_DIR,
    TEMPLATE_DIR,
    LETSENCRYPT_LIVE_DIR,
    LETSENCRYPT_OPTIONS_SSL,
    LETSENCRYPT_SSL_DHPARAM,
    DEFAULT_CLIENT_MAX_BODY_SIZE,
    DEFAULT_HSTS_MAX_AGE,
    WAF_MAIN_CONF
)


class NginxManager:
    """Manages NGINX configurations and operations"""

    def __init__(self):
        self.conf_dir = NGINX_CONF_DIR
        self.template_dir = TEMPLATE_DIR
        self.env = Environment(loader=FileSystemLoader(str(self.template_dir)))

    def create_temp_config(self, fqdn: str, external_port: int = 443) -> Path:
        """
        Create temporary HTTP configuration for certificate generation

        Args:
            fqdn: Fully qualified domain name
            external_port: External port number

        Returns:
            Path to created configuration file
        """
        template = self.env.get_template('temp_http.conf.j2')
        content = template.render(
            fqdn=fqdn,
            external_port=external_port
        )

        conf_file = self.conf_dir / f"{fqdn}.conf"
        conf_file.write_text(content)
        return conf_file

    def create_config(
        self,
        fqdn: str,
        internal_ip: str,
        internal_port: int,
        external_port: int = 443,
        forward_scheme: str = "http",
        websockets_enabled: bool = False,
        waf_enabled: bool = False,
        client_max_body_size: str = DEFAULT_CLIENT_MAX_BODY_SIZE,
        hsts_max_age: int = DEFAULT_HSTS_MAX_AGE
    ) -> Path:
        """
        Create final NGINX configuration

        Args:
            fqdn: Fully qualified domain name
            internal_ip: Internal server IP
            internal_port: Internal server port
            external_port: External port (default: 443)
            forward_scheme: http or https (default: http)
            websockets_enabled: Enable websocket headers (default: False)
            waf_enabled: Enable Coraza WAF with global rule set (default: False)
            client_max_body_size: Maximum upload size (default: 100M)
            hsts_max_age: HSTS max age in seconds (default: 31536000)

        Returns:
            Path to created configuration file
        """
        # Determine which template to use
        if external_port == 443:
            template_name = 'nginx_standard.conf.j2'
        else:
            template_name = 'nginx_custom_port.conf.j2'

        template = self.env.get_template(template_name)

        # Prepare certificate paths
        ssl_certificate = LETSENCRYPT_LIVE_DIR / fqdn / "fullchain.pem"
        ssl_certificate_key = LETSENCRYPT_LIVE_DIR / fqdn / "privkey.pem"

        # Render template
        content = template.render(
            fqdn=fqdn,
            internal_ip=internal_ip,
            internal_port=internal_port,
            external_port=external_port,
            forward_scheme=forward_scheme,
            websockets_enabled=websockets_enabled,
            waf_enabled=waf_enabled,
            waf_main_conf=WAF_MAIN_CONF,
            ssl_certificate=ssl_certificate,
            ssl_certificate_key=ssl_certificate_key,
            ssl_options=LETSENCRYPT_OPTIONS_SSL,
            ssl_dhparam=LETSENCRYPT_SSL_DHPARAM,
            client_max_body_size=client_max_body_size,
            hsts_max_age=hsts_max_age
        )

        conf_file = self.conf_dir / f"{fqdn}.conf"
        conf_file.write_text(content)
        return conf_file

    def remove_config(self, fqdn: str) -> bool:
        """
        Remove NGINX configuration file

        Args:
            fqdn: Fully qualified domain name

        Returns:
            True if removed, False if not found
        """
        conf_file = self.conf_dir / f"{fqdn}.conf"
        if conf_file.exists():
            conf_file.unlink()
            return True
        return False

    def reload(self) -> bool:
        """
        Reload NGINX configuration

        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run(
                ["nginx", "-s", "reload"],
                check=True,
                capture_output=True,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error reloading NGINX: {e.stderr}")
            return False

    def test_config(self) -> bool:
        """
        Test NGINX configuration

        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            result = subprocess.run(
                ["nginx", "-t"],
                check=True,
                capture_output=True,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"NGINX configuration test failed:\n{e.stderr}")
            return False

    def list_configs(self) -> list[str]:
        """
        List all configured domains

        Returns:
            List of domain names
        """
        if not self.conf_dir.exists():
            return []

        configs = []
        for conf_file in self.conf_dir.glob("*.conf"):
            # Skip catch-all configuration
            if conf_file.name != "catch-all.conf":
                configs.append(conf_file.stem)

        return sorted(configs)
