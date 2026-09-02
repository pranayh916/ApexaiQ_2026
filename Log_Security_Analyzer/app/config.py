import json
from pathlib import Path


class SecurityConfig:

    def __init__(self, config_path):
        self.config_path = Path(config_path)
        self.data = self.load_config()

    def load_config(self):
        with open(self.config_path, "r", encoding="utf-8") as file:
            return json.load(file)

    def get_rule(self, rule_name):
        return self.data["rules"].get(rule_name)

    def get_trusted_locations(self, username):
        return self.data["trusted_locations"].get(username, [])