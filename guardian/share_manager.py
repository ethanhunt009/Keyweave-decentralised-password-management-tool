import json
import os
import base64
import config

class ShareManager:
    def __init__(self):
        self.shares = {}
        self.storage_file = os.path.join(
            config.Config.GUARDIAN_STORAGE, 
            f"shares_{os.environ.get('GUARDIAN_PORT', 'default')}.json"
        )
        self._load_shares()
    
    def _load_shares(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, "r") as f:
                self.shares = json.load(f)
    
    def _save_shares(self):
        with open(self.storage_file, "w") as f:
            json.dump(self.shares, f, indent=2)
    
    def store_share(self, vault_id, share_index, share):
        if vault_id not in self.shares:
            self.shares[vault_id] = {}
        
        self.shares[vault_id][share_index] = base64.b64encode(share).decode('utf-8')
        self._save_shares()
    
    def get_share_for_recovery(self, recovery_id):
        # Extract vault_id from recovery_id (in real system would use mapping)
        vault_id = recovery_id[:16]  # Simplified for research
        
        if vault_id in self.shares and self.shares[vault_id]:
            # Return first share for this vault
            share_index, share_b64 = next(iter(self.shares[vault_id].items()))
            return {
                "share": base64.b64decode(share_b64),
                "share_index": share_index
            }
        return None
    
    def count_shares(self):
        count = 0
        for vault in self.shares.values():
            count += len(vault)
        return count