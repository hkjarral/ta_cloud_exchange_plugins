"""Illumio Plugin implementation to pull data from Illumio Platform."""

from netskope_integrations import PluginBase, PluginOptions
from data_objects import ValidationResult
from illuminet.client import IllumioApiClient
from illuminet.config import IllumioConfig
from illuminet.data import IllumioData

class IllumioPlugin(PluginBase):
    def __init__(self):
        self.config = IllumioConfig()
        self.client = IllumioApiClient(self.config)
        self.data = None

    def init(self, options):
        self.config.init_config(options)

    def validate(self):
        if not self.config.api_key:
            return ValidationResult(success=False, message="Missing API key")
        if not self.config.api_secret:
            return ValidationResult(success=False, message="Missing API secret")
        try:
            self.client.test_connection()
            return ValidationResult(success=True, message="Validation successful.")
        except Exception as e:
            return ValidationResult(success=False, message=f"Validation failed: {e}")

    def fetch(self):
        self.data = IllumioData()
        self.data.workloads = self.client.get_workloads()
        self.data.labels = self.client.get_labels()
        self.data.flows = self.client.get_flows()

    def process(self):
        if not self.data:
            raise Exception("No data fetched")
        transformed_data = self.data.transform()
        for record in transformed_data:
            self.send_data(record)

            
            
if __name__ == "__main__":
plugin = IllumioPlugin()
options = PluginOptions()
plugin.run(options)

