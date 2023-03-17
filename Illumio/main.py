"""Illumio Plugin implementation to pull Label data from Policy Compute Engine"""

import requests
import datetime
import time
from datetime import timedelta
from requests.auth import HTTPBasicAuth
import json
from typing import List


from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)

from netskope.integrations.cte.utils import TagUtils

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.common.utils import add_user_agent

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

    def _create_tags(
        self, utils: TagUtils, tags: List,
    ) -> (List[str]):
        """Create new tag(s) in database if required."""
        tag_names = []
        for tag in tags:
            try:
                if not utils.exists(tag.strip()):
                    utils.create_tag(
                        TagIn(
                            name=tag.strip(),
                            color="#ED3347",
                        )
                    )
            except ValueError as e:
                self.logger.error(f"Illumio Error: {e}")
            else:
                tag_names.append(tag.strip())
        tag_names = set(tag_names)
        return list(tag_names)


    def pull(self):
        """Pull the Label information from Illumio platform.
        List of Labels from the Illumio platform.
        """
        self.configuration["key_id"] = self.configuration[
            "key_id"
            ].replace(
            " ", "")
        self.configuration["key_secret"] = self.configuration[
            "key_secret"
            ].replace(
            " ", ""
        )
        try:
            auth_json = self.get_auth_json(
                self.configuration.get("key_id"),
                self.configuration.get("key_secret"),
            )
            auth_token = auth_json.get("access_token")
            headers = {
                "accept": "application/json",
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            return self.get_indicators(headers)

        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: Illumio, Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: Illumio, Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: Illumio, Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: Illumio, "
                "Unable to establish connection with Illumio platform. "
                "Proxy server or Illumio API is not reachable."
            )
            self.logger.error(
                "Plugin: Illumio, "
                "Unable to establish connection with Illumio platform. "
                "Proxy server or Illumio API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: Illumio, "
                "Unable to establish connection with Illumio platform. "
                "Proxy server or Illumio API is not reachable."
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: Illumio, "
                "Exception occurred while making an API call to "
                "Illumio platform"
            )
            raise e
        except AuthenticationException as e:
            raise e
