import uuid
import hashlib
import requests

class Guardian:
    def __init__(self, name):
        self.name = name
        self.did = f"did:example:{uuid.uuid4()}"
        self.shard = None
        self.commitment = None
        self.cid = None

    def receive_shard_ipfs(self, cid):
        """Fetch shard from IPFS using CID via HTTP."""
        response = requests.post(f"http://127.0.0.1:5001/api/v0/cat?arg={cid}")
        response.raise_for_status()
        shard_string = response.content.decode('utf-8')
        x, y = map(int, shard_string.split(','))
        self.shard = (x, y)
        self.commitment = hashlib.sha256(shard_string.encode()).hexdigest()
        self.cid = cid
        print(f"  [Guardian {self.name}] Received IPFS shard CID: {cid[:10]}... Commitment: {self.commitment[:10]}...")

    def provide_proof(self):
        print(f"  [Guardian {self.name}] Providing proof of shard knowledge.")
        return {"did": self.did, "commitment": self.commitment}

    def provide_shard_for_reconstruction(self):
        print(f"  [Guardian {self.name}] Proof accepted. Providing shard for reconstruction.")
        return self.shard
class RecoveryPolicy:
    """
    Represents a user's recovery policy, like a Verifiable Credential.
    """
    def __init__(self, threshold, guardian_dids):
        self.threshold = threshold
        self.num_guardians = len(guardian_dids)
        self.authorized_dids = set(guardian_dids)
        print(f"[Policy Created] Recovery requires {self.threshold} of {self.num_guardians} specific guardians.")
