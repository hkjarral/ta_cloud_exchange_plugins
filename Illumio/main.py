from typing import Dict
from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
)


class MyPluginConfigValidator(PluginConfigValidator):
    def validate(self, config: Dict) -> ValidationResult:
        required_keys = ["url", "username", "password"]
        for key in required_keys:
            if key not in config:
                return ValidationResult(
                    success=False, message=f"Missing required key '{key}' in plugin config."
                )
        return ValidationResult(success=True, message="Validation successful.")
