import json
import logging
import requests

from typing import Dict, Any
from requests.exceptions import RequestException
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult


class IllumioLabelPlugin(PluginBase):
    """
    This plugin retrieves labels from the Illumio API based on the provided configuration.
    """

    def __init__(self, configuration: Dict[str, Any]):
        super().__init__(configuration)

        # Set up logger
        self.logger = logging.getLogger(__name__)

        # Check if required configuration parameters are present
        if "api_url" not in self.configuration:
            self.logger.error("API URL is missing from configuration.")
            raise ValueError("API URL is missing from configuration.")
        if "api_username" not in self.configuration:
            self.logger.error("API Username is missing from configuration.")
            raise ValueError("API Username is missing from configuration.")
        if "api_password" not in self.configuration:
            self.logger.error("API Password is missing from configuration.")
            raise ValueError("API Password is missing from configuration.")
        if "org_id" not in self.configuration:
            self.logger.error("Organization ID is missing from configuration.")
            raise ValueError("Organization ID is missing from configuration.")
        if "label_id" not in self.configuration:
            self.logger.error("Label ID is missing from configuration.")
            raise ValueError("Label ID is missing from configuration.")

    def validate_configuration(self) -> ValidationResult:
        """
        Validates the plugin configuration.

        Returns:
            A ValidationResult object indicating whether the validation was successful and, if not, the reason for failure.
        """
        if not isinstance(self.configuration["api_password"], str):
            return ValidationResult(success=False, message="API username must be a string.")
        if not isinstance(self.configuration["api_username"], str):
            return ValidationResult(success=False, message="API secret must be a string.")
        if not isinstance(self.configuration["api_url"], str):
            return ValidationResult(success=False, message="API url must be a string.")
        if not isinstance(self.configuration["org_id"].isdigit()):
            return ValidationResult(success=False, message="Organization ID must be a string.")
        if not isinstance(self.configuration["label_id"], str):
            return ValidationResult(success=False, message="Label ID must be a string.")
        return ValidationResult(success=True, message="Validation successful.")

    def pull_labels(self) -> Dict[str, str]:
        """
        Retrieves all labels from the Illumio API.

        Returns:
            A dictionary containing the labels and their IDs.
        """
        labels = (self.configuration["label_id"])
        try:
            response = requests.get(
                url=f"{self.configuration['api_endpoint']}/api/v2/orgs/{self.configuration['org_id']}/labels",
                auth=(self.configuration["api_key"], self.configuration["api_secret"]),
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            for label in data:
                labels[label["name"]] = label["id"]
            return labels
        except RequestException as e:
            self.logger.error(f"Failed to retrieve labels from Illumio API: {e}")
            raise ValueError(f"Failed to retrieve labels from Illumio API: {e}")

    def run(self) -> None:
        """
        Runs the plugin.
        """
        labels = self.pull_labels()
        print(json.dumps(labels, indent=4))
