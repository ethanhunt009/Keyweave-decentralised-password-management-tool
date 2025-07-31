import json
import os
import config

class SecureStorage:
    def __init__(self):
        self.storage_file = os.path.join(config.Config.DATA_DIR, "client_vaults.json")
        self.vaults = self._load_data()
    
    def _load_data(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, "r") as f:
                return json.load(f)
        return {}
    
    def _save_data(self):
        with open(self.storage_file, "w") as f:
            json.dump(self.vaults, f, indent=2)
    
    def store_vault(self, vault_id, **data):
        self.vaults[vault_id] = data
        self._save_data()
    
    def get_vault(self, vault_id):
        return self.vaults.get(vault_id)
    
    def list_vaults(self):
        return list(self.vaults.keys())