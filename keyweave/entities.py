import uuid
import hashlib
import requests
from cryptography.fernet import Fernet

class Guardian:
    """
    Represents a Guardian in the KeyWeave network.
    Runtime registration supported with 5 predefined guardians.
    """
    registry = {}

    def __init__(self, name=None):
        if name is None:
            name = input("Enter guardian name to register: ")
        self.name = name
        self.did = f"did:example:{uuid.uuid4()}"
        self.shard = None
        self.commitment = None
        self.cid = None
        Guardian.registry[self.did] = self
        print(f"[Guardian Registered] {self.name} with DID {self.did[:15]}...")

    def receive_shard_ipfs(self, cid, fernet_key):
        """Fetch encrypted shard from IPFS and decrypt using Fernet."""
        response = requests.post(f"http://127.0.0.1:5001/api/v0/cat?arg={cid}")
        response.raise_for_status()
        encrypted_data = response.content

        f = Fernet(fernet_key)
        shard_string = f.decrypt(encrypted_data).decode('utf-8')

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

    @classmethod
    def get_by_did(cls, did):
        return cls.registry.get(did)

# Fernet key for encryption (shared across guardians)
FERNET_KEY = Fernet.generate_key()

# Predefined Guardians
PREDEFINED_GUARDIANS = [
    Guardian("Alice (Family)"),
    Guardian("Bob (Friend)"),
    Guardian("Charlie (Lawyer)"),
    Guardian("David (Friend)"),
    Guardian("Eve (Colleague)")
]

class RecoveryPolicy:
    """
    Represents a user's recovery policy, like a Verifiable Credential.
    Runtime threshold selection supported.
    """
    def __init__(self, guardian_dids):
        self.num_guardians = len(guardian_dids)
        while True:
            try:
                threshold = int(input(f"Enter recovery threshold (1-{self.num_guardians}): "))
                if 1 <= threshold <= self.num_guardians:
                    self.threshold = threshold
                    break
                else:
                    print("Threshold must be within the number of guardians.")
            except ValueError:
                print("Invalid input. Please enter a number.")

        self.authorized_dids = set(guardian_dids)
        print(f"[Policy Created] Recovery requires {self.threshold} of {self.num_guardians} specific guardians.")
