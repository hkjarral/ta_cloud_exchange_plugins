"""Illumio Plugin implementation to pull Label data from Policy Compute Engine"""

import requests
import datetime
import time
from datetime import timedelta
from requests.auth import HTTPBasicAuth
import json
from typing import List


from netskope.integrations.cte.models import TagIn
from netskope.integrations.cte.utils import TagUtils

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)

class AuthenticationException(Exception):
    pass

class IllumioPlugin(PluginBase):
    """Illumio Plugin class for pulling Label information."""

    def handle_error(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object
            returned from API call.
        Returns:
            dict: Returns the dictionary of response JSON
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                self.notifier.error(
                    "Plugin: Illumio, "
                    "Exception occurred while parsing JSON response."
                )
                self.logger.error(
                    "Plugin: Illumio, "
                    "Exception occurred while parsing JSON response."
                )
        if resp.status_code == 204:
            return {}
        elif resp.status_code == 400:
            auth_reponse = resp.text
            result_dict = json.loads(auth_reponse)
            err_msg = result_dict["error"]
            if(
                "errorMessage" in result_dict
                and err_msg == "invalid_basic_auth"
            ):
                raise AuthenticationException(
                    "Invalid Key ID or Key Secret Provided."
                )
            else:
                self.notifier.error(
                        "Plugin: Illumio, "
                        "Received exit code 400, Bad Request."
                    )
                self.logger.error(
                        "Plugin: Illumio, "
                        "Received exit code 400, Bad Request"
                )
        elif resp.status_code == 403:
            self.notifier.error(
                "Plugin: Illumio, "
                "Received exit code 403, Forbidden User"
            )
            self.logger.error(
                "Plugin: Illumio, "
                "Received exit code 403, Forbidden User"
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.notifier.error(
                f"Plugin: Illumio, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
            self.logger.error(
                f"Plugin: Illumio, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.notifier.error(
                f"Plugin: Illumio, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
            self.logger.error(
                f"Plugin: Illumio, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
        resp.raise_for_status()

   
