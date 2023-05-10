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
from .lib.illumio import *

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
        config = self.configuration
        pce = PolicyComputeEngine('config["api_url"]', port='config["port"]', org_id='config["org_id"]')
        pce.set_credentials('config["api_username"]', 'config["api_password"]')
        full_api_url = (config["api_url"] + '/api/v2/orgs/' + str(config["org_id"]) + '/workloads')

        headers = {
            'Accept': 'application/json'
        }
        auth = (str(config["api_username"]), str(config["api_password"]))

        response = requests.get(full_api_url , headers=headers, auth=auth)
        data = self.handle_error(response)
        indicators = []

        # Parse the JSON response to extract the workloads
        json_response = json.loads(response.text)

        # Extract value of Location Label from each array of the output.
        for i in range(0, len(json_response)):
            labels = jsonpath.jsonpath(json_response[i], 'labels[2].value')

            # Check if Location Label is set to "quarantine" if it is return public ip of workload
            if (labels[0]) == config["label_id"]:
                try:
                    public_ip = (jsonpath.jsonpath(json_response[i], 'public_ip'))
                    indicators.append(Indicator(value=public_ip[0],type=IndicatorType.URL,))

                except ValidationError as err:
                        self.logger.error(
                        message=f"{PLUGIN_NAME}: Error occurred while pulling Labels. Hence skipping {url}",
                        details=f"Error Details: {err}",
                        )
        return indicators

    def validate(self, data):
        """Validate the Plugin configuration parameters.
        Validation for all the parameters mentioned in the manifest.json for the existence and
        data type. Method returns the cte.plugin_base.ValidationResult object with success = True in the case
        of successful validation and success = False and a error message in the case of failure.
        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        config = self.configuration
        pce = PolicyComputeEngine('config["api_url"]', port='config["port"]', org_id='config["org_id"]')
        pce.set_credentials('config["api_username"]', 'config["api_password"]')
        self.logger.info("Sample Plugin: Executing validate method for Sample plugin")
        if (
                "api_password" not in data
                or not isinstance(data["api_password"], str)
        ):
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: API password is required with type string."
            )
            return ValidationResult(
                success=False, message="Invalid API password provided."
            )
        elif (
                "api_username" not in data
                or not isinstance(data["api_username"], str)
        ):
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: API username is required with type string."
            )
            return ValidationResult(
                success=False, message="Invalid API username provided."
            )
        elif (
                "api_url" not in data
                or not isinstance(data["api_url"], str)
        ):
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: API URL is required with type string."
            )
            return ValidationResult(
                success=False, message="Invalid API URL provided."
            )
        elif (
                "org_id" not in data
                or not isinstance(data["org_id"],int)
        ):
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: Organization ID is required with digits."
            )
            return ValidationResult(
                success=False, message="Invalid Organization ID provided."
            )
        elif (
                "label_id" not in data
                or not isinstance(data["label_id"], str)
        ):
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: Label ID is required with type string."
            )
            return ValidationResult(
                success=False, message="Invalid Label ID provided."
            )
        elif not pce.check_connection()(
            self.logger.error(
                "Illumio Plugin: API Connection Failed - Check credentials."
            ))
            return ValidationResult(
                success=False, message="Invalid credentials provided."
            )
        else:
            return ValidationResult(
                success=True, message="Validation Successful for Illumio plugin"
            )
