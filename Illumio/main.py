"""Illumio Plugin providing implementation for pull and validate methods from PluginBase."""
import json
import requests
import jsonpath
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.common.utils import add_user_agent
from pydantic import ValidationError
import requests

PLUGIN_NAME = "Illumio"


class IllumioException(Exception):
    """Illumio Exception class."""

    pass


class IllumioPlugin(PluginBase):
    """Illumio class template implementation."""

    def handle_error(self, resp: requests.models.Response):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API
            call.
        Returns:
            dict: Returns the dictionary of response JSON when the response
            code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        err_msg = f"Response code {resp.status_code} received."
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                self.logger.error(
                    f"{PLUGIN_NAME}: Response is not JSON format. "
                )
                raise IllumioException(
                    f"{PLUGIN_NAME}: Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 401:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise IllumioException(
                f"{PLUGIN_NAME}: Received exit code 401, Authentication Error"
            )
        elif resp.status_code == 403:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise IllumioException(
                f"{PLUGIN_NAME}: Received exit code 403, Forbidden User"
            )
        elif resp.status_code == 404:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise IllumioException(
                f"{PLUGIN_NAME}: Received exit code 404, Not Found"
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise IllumioException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP client Error"
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise IllumioException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise IllumioException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP Error"
            )

    def pull(self):
        """Pull Labels from PCE"""

        """Get all content from location configured on the plugin"""
        api_url = (self.configuration.get(api_url) + '/api/v2/orgs' + self.configuration.get(org_id) + '/workloads')

        headers = {
            'Accept': 'application/json'
        }
        auth = (self.configuration.get(api_username), self.configuration.get(api_password))

        response = requests.get(api_url , headers=headers, auth=auth)
        data = self.handle_error(response)
        indicators = []

        # Parse the JSON response to extract the workloads
        json_response = json.loads(response.text)

        # Extract value of Location Label from each array of the output.
        for i in range(0, len(json_response)):
            labels = jsonpath.jsonpath(json_response[i], 'labels[2].value')

            # Check if Location Label is set to "quarantine" if it is return public ip of workload
            if (labels[0]) == self.configuration.get(label_id):
                try:
                    public_ip = (jsonpath.jsonpath(json_response[i], 'public_ip'))
                    indicators.append(Indicator(value=public_ip[0],type=IndicatorType.URL,))

                except ValidationError as err:
                        self.logger.error(
                        message=f"{PLUGIN_NAME}: Error occurred while pulling Labels. Hence skipping {url}",
                        details=f"Error Details: {err}",
                        )
        return indicators

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.
        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        err_msg = None
        if (
                "api_url" not in configuration
                or type(configuration.get(api_url)) != str
                or not configuration["api_url"].strip()
        ):
            err_msg = "API URL is Required Field."

        if configuration["api_url"] not in REGIONS:
            err_msg = "Invalid URL Provided"

        if (
                "label_id" not in configuration
                or type(configuration.get("label_id")) != str
        ):
            err_msg = "Label Field is required"

        if not err_msg:
            return ValidationResult(
                success=True,
                message=f"{PLUGIN_NAME}: Validation Successful.",
            )
        else:
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred, Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
