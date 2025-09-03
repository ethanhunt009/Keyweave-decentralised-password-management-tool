# ----- entities.py -----
import uuid
import hashlib
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class Guardian:
    """
    Represents a Guardian in the KeyWeave network with RSA encryption.
    Each guardian generates their own RSA key pair.
    """
    registry = {}

    def __init__(self, name=None):
        if name is None:
            name = input("Enter guardian name to register: ")
        self.name = name
        self.did = f"did:example:{uuid.uuid4()}"
        self.shards = {}  # Now stores multiple shards for different accounts
        self.commitments = {}  # Commitments for each account
        self.cids = {}  # CIDs for each account
        
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Serialize public key for distribution
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        Guardian.registry[self.did] = self
        print(f"[Guardian Registered] {self.name} with DID {self.did[:15]}...")
        print(f"  Generated RSA key pair")

    def receive_shard_ipfs(self, cid, account_name):
        """Fetch encrypted shard from IPFS and decrypt using private key."""
        try:
            response = requests.post(f"http://127.0.0.1:5001/api/v0/cat?arg={cid}", timeout=10)
            response.raise_for_status()
            encrypted_data = response.content
            
            # Decrypt with private key
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
            
            shard_string = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')

            x, y = map(int, shard_string.split(','))
            self.shards[account_name] = (x, y)
            self.commitments[account_name] = hashlib.sha256(shard_string.encode()).hexdigest()
            self.cids[account_name] = cid
            print(f"  [Guardian {self.name}] Received IPFS shard CID for {account_name}: {cid[:10]}...")
            print(f"  Decrypted shard with private key. Commitment: {self.commitments[account_name][:10]}...")
            return True
        except requests.exceptions.Timeout:
            print(f"  [Guardian {self.name}] Timeout while fetching shard from IPFS.")
            return False
        except requests.exceptions.RequestException as e:
            print(f"  [Guardian {self.name}] Error fetching shard from IPFS: {e}")
            return False
        except Exception as e:
            print(f"  [Guardian {self.name}] Failed to decrypt shard: {e}")
            return False

    def provide_proof(self, account_name):
        print(f"  [Guardian {self.name}] Providing proof of shard knowledge for {account_name}.")
        return {"did": self.did, "commitment": self.commitments.get(account_name, "unknown")}

    def provide_shard_for_reconstruction(self, account_name):
        print(f"  [Guardian {self.name}] Proof accepted. Providing shard for {account_name} reconstruction.")
        return self.shards.get(account_name)

    @classmethod
    def get_by_did(cls, did):
        return cls.registry.get(did)

# Predefined Guardians (generate with RSA keys)
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
        
        # Check if there are any guardians
        if self.num_guardians == 0:
            print("❌ No guardians available. Please add guardians first.")
            self.threshold = 0
            self.authorized_dids = set()
            return
            
        while True:
            try:
                threshold = int(input(f"Enter recovery threshold (1-{self.num_guardians}): "))
                if 1 <= threshold <= self.num_guardians:
                    self.threshold = threshold
                    break
                else:
                    print(f"Threshold must be between 1 and {self.num_guardians}.")
            except ValueError:
                print("Invalid input. Please enter a number.")

        self.authorized_dids = set(guardian_dids)
        print(f"[Policy Created] Recovery requires {self.threshold} of {self.num_guardians} specific guardians.")