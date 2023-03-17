"""
BSD 3-Clause License.

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
