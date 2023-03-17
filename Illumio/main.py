import requests
from datetime import datetime
from typing import Dict, Any, Optional
from ta_cloud_exchange_plugins.sdk.plugin_base import PluginBase, ValidationResult


class IllumioLabelsPlugin(PluginBase):
    """
    This plugin retrieves labels from the Illumio API.
    """

    def __init__(self, name: str, configuration: Optional[Dict[str, Any]] = None):
        super().__init__(name, configuration)

        # API endpoint for getting labels
    """ self.labels_api = "https://api.illumio.com/api/v2/orgs/{}/labels" """
        self.labels_api = "{self.configuration[api_url]}/api/v2/orgs/{self.configuration[org_id]}/labels"

    def validate_configuration(self) -> ValidationResult:
        """
        Validate the plugin configuration.
        """
        # Ensure the org_id is provided and is a string
        if "org_id" not in self.configuration:
            return ValidationResult(success=False, message="Missing org_id in configuration.")
        elif not isinstance(self.configuration["org_id"].isdigit()):
            return ValidationResult(success=False, message="org_id must be digits.")
        return ValidationResult(success=True, message="Configuration validated successfully.")

    def get_labels(self) -> Dict[str, str]:
        """
        Retrieve the labels from the API and return them as a dictionary.
        """
        org_id = self.configuration["org_id"]
        headers = {"Authorization": "Bearer " + self.get_api_key(), "Accept": "application/json"}
        response = requests.get(self.labels_api.format(org_id), headers=headers)
        response.raise_for_status()
        labels = {}
        for label in response.json()["results"]:
            labels[label["id"]] = label["name"]
        return labels

    def get(self) -> Dict[str, Any]:
        """
        Get the labels from the API and return them as a dictionary with the current time.
        """
        labels = self.get_labels()
        return {"labels": labels, "timestamp": datetime.utcnow().isoformat()}
