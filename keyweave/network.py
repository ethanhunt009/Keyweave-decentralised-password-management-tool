# --- Updated network.py with modern IPFS support using requests ---

import requests
from .crypto import shamir_split_secret, shamir_reconstruct_secret

class IPFSClient:
    def __init__(self, api_url='http://127.0.0.1:5001'):
        self.api_url = api_url

    def add_str(self, data):
        files = {'file': ('shard.txt', data)}
        response = requests.post(f'{self.api_url}/api/v0/add', files=files)
        response.raise_for_status()
        return response.json()['Hash']

    def cat(self, cid):
        response = requests.post(f'{self.api_url}/api/v0/cat?arg={cid}')
        response.raise_for_status()
        return response.content

class KeyWeaveNetwork:
    """
    Orchestrates the KeyWeave process, acting as the decentralized network.
    Now stores shards in IPFS using HTTP API.
    """
    def __init__(self):
        self.guardian_commitments = {}
        self.ipfs_client = IPFSClient()  # Uses HTTP API to connect to IPFS

    def setup_escrow(self, secret, policy, guardians):
        print("\n--- Initiating KeyWeave Setup ---")
        if policy.num_guardians != len(guardians):
            raise ValueError("Policy must match the number of provided guardians.")

        shares = shamir_split_secret(secret, policy.threshold, policy.num_guardians)
        print(f"[KeyWeave] Secret split into {len(shares)} shares.")

        for i, guardian in enumerate(guardians):
            shard = shares[i]
            shard_data = f"{shard[0]},{shard[1]}"
            # Upload shard to IPFS
            cid = self.ipfs_client.add_str(shard_data)
            print(f"[IPFS] Uploaded shard for {guardian.name}, CID: {cid}")
            guardian.receive_shard_ipfs(cid)
            self.guardian_commitments[guardian.did] = guardian.commitment

        print("[KeyWeave] All shares uploaded to IPFS and commitments recorded.")

    def initiate_recovery(self, recovery_guardians, policy):
        print(f"\n--- Initiating KeyWeave Recovery for {len(recovery_guardians)} guardians ---")
        if len(recovery_guardians) < policy.threshold:
            print(f"[KeyWeave] RECOVERY FAILED: Not enough guardians. Need {policy.threshold}, got {len(recovery_guardians)}.")
            return None

        valid_proofs = 0
        shards_for_reconstruction = []

        print(f"[KeyWeave] Collecting and verifying proofs...")
        for guardian in recovery_guardians:
            proof = guardian.provide_proof()
            guardian_did = proof["did"]
            guardian_commitment = proof["commitment"]

            if guardian_did in policy.authorized_dids and self.guardian_commitments.get(guardian_did) == guardian_commitment:
                print(f"  [KeyWeave] Proof from Guardian {guardian.name} ({guardian_did[:10]}...) is VALID.")
                valid_proofs += 1
                shards_for_reconstruction.append(guardian.provide_shard_for_reconstruction())
            else:
                print(f"  [KeyWeave] Proof from Guardian {guardian.name} is INVALID.")

        if valid_proofs >= policy.threshold:
            print(f"[KeyWeave] Success! {valid_proofs} valid proofs collected, meeting the threshold of {policy.threshold}.")
            reconstructed_secret = shamir_reconstruct_secret(shards_for_reconstruction)
            print("[KeyWeave] RECOVERY SUCCESSFUL!")
            return reconstructed_secret
        else:
            print(f"[KeyWeave] RECOVERY FAILED: Only {valid_proofs} valid proofs, but threshold is {policy.threshold}.")
            return None
