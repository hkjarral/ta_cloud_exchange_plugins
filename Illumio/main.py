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
                f"{PLUGIN_NAME}: Received exit code 401, Authentication Error - Authentication failure or HTTP/1.1 401 Unauthorized"
            )
        elif resp.status_code == 403:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise IllumioException(
                f"{PLUGIN_NAME}: Received exit code 403, Forbidden User - Authorization failure"
            )
        elif resp.status_code == 404:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise IllumioException(
                f"{PLUGIN_NAME}: Received exit code 404, Not Found - Invalid URL"
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            raise IllumioException(
                f"{PLUGIN_NAME}: Received exit code {resp.status_code}, HTTP client Error - Bad Request - Invalid URL or Method not allowed or Invalid Payload"
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
        pce = PolicyComputeEngine(config["api_url"], port=config["api_port"], org_id=config["org_id"])
        pce.set_credentials(config["api_username"], config["api_password"])
        self.logger.info("PCE Connection Status: {}".format(pce.check_connection()))
        labels = pce.labels.get(params={"value": config["label_id"]})
        self.logger.info("Labels Output: {}".format(labels))
        refs = [[label.href for label in labels]]
        self.logger.info("Refs Output: {}".format(refs))
        workloads = pce.workloads.get(params={'labels': json.dumps(refs)})
        indicators = []

        for workload in workloads:
            for interface in workload.interfaces:
                try:
                    self.logger.info(f"Successfully retrieved IP: {interface.address}")
                    indicators.append(Indicator(value=interface.address, type=IndicatorType.URL))
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
        self.logger.info("Illumio Plugin: Executing validate method for Sample plugin")
        if "api_url" not in data or not isinstance(data["api_url"], str) or not data["api_url"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: API URL is required."
            )
            return ValidationResult(success=False, message="Invalid API URL provided.")
        elif "api_username" not in data or not isinstance(data["api_username"], str) or not data["api_username"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: API Username is required with type string."
            )
            return ValidationResult(success=False, message="Invalid API Username provided.")
        elif "api_password" not in data or not isinstance(data["api_password"], str) or not data["api_password"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: API Password is required with type string."
            )
            return ValidationResult(success=False, message="Invalid API Password provided.")
        elif "org_id" not in data or not isinstance(data["org_id"], int) or not data["org_id"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: Org ID is required with type int."
            )
            return ValidationResult(success=False, message="Invalid Org ID provided.")
        elif "api_port" not in data or not isinstance(data["api_port"], int) or not data["api_port"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: Port should be an integer."
            )
            return ValidationResult(success=False, message="Invalid Port provided.")
        elif "label_id" not in data or not isinstance(data["label_id"], str) or not data["label_id"]:
            self.logger.error(
                "Illumio Plugin: Validation error occurred Error: Label ID is required with type string."
            )
            return ValidationResult(success=False, message="Invalid Label ID provided.")
        else:
            return ValidationResult(success=True, message="Validation successful.")
