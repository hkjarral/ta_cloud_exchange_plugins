"""
Illumio Plugin implementation to pull the data from
Illumio Platform.
"""

import datetime
import time
import hmac
import hashlib
import base64
import requests
import urllib.parse
from typing import Dict, List
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.utils import TagUtils


class IllumioPlugin(PluginBase):
    """Illumio Plugin Base Class.

    Args:
        PluginBase (PluginBase): Inherit PluginBase Class from Cloud
        Threat Exchange Integration.
    """

    def handle_error(self, resp) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API.
        Returns:
            dict: Returns the dictionary of response JSON when response is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                self.logger.error(
                    "Plugin: Illumio, "
                    "Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 401:
            self.logger.error(
                "Plugin: Illumio, Received exit code 401, "
                "Authentication Error."
            )
        elif resp.status_code == 403:
            self.logger.error(
                "Plugin: Illumio, "
                "Received exit code 403, Forbidden User."
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.logger.error(
                f"Plugin: Illumio, "
                f"Received exit code {resp.status_code}, HTTP client Error."
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.logger.error(
                f"Plugin: Illumio, "
                f"Received exit code {resp.status_code}, HTTP server Error."
            )
        else:
            self.logger.error(
                f"Plugin: Illumio, "
                f"Received exit code {resp.status_code}, HTTP Error."
            )
        resp.raise_for_status()

    def get_pull_request(self, api_url):
        """Make pull request to get data from Illumio.
        Args:
            api_url (str): API url endpoint.
        Returns:
            Response: Return API response.
        """
        headers = self._get_headers_for_auth(
            api_url,
            self.configuration["auth_username"],
            self.configuration["auth_password"],
            "GET",
        )
        query_endpoint = self.configuration["api_url"] + org
        ioc_response = self._api_calls(
            requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            ),
        )
        return ioc_response

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration.
        Args:
            configuration(dict): Configuration from manifest.json.
        Returns:
            ValidationResult: Valid configuration fields or not.
        """
        # Base URL
        if (
                "api_url" not in configuration
                or not isinstance(configuration["api_url"], str)
                or not configuration["api_url"].strip()
                or not self._validate_url(configuration["api_url"])
        ):
            self.logger.error(
                "Illumio Plugin: "
                "Invalid Base URL found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Base URL provided.",
            )
        # auth_username
        if (
                "auth_username" not in configuration
                or not isinstance(configuration["auth_username"], str)
                or not configuration["auth_username"].strip()
        ):
            self.logger.error(
                "Illumio Plugin: "
                "Invalid Access ID found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Access ID provided.",
            )
        # Secret Key
        if (
                "auth_password" not in configuration
                or not isinstance(configuration["auth_password"], str)
                or not configuration["auth_password"].strip()
        ):
            self.logger.error(
                "Illumio Plugin: "
                "No Secret key found in configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Secret key provided."
            )
        # Organization ID
        if (
                "org_id" not in configuration
                or not isinstance(configuration["org_id"].isdigit)
        ):
            self.logger.error(
                "Illumio Plugin: "
                "Organization ID is invalid"
            )
            return ValidationResult(
                success=False, message="Invalid Organization ID provided."
            )

        if not self._is_valid_credentials(
                configuration["api_url"],
                configuration["auth_username"],
                configuration["auth_password"],
        ):
            return ValidationResult(
                success=False,
                message="Invalid Access ID or Secret key provided.",
            )
        
