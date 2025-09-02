# ----- main.py -----
from keyweave.entities import Guardian, RecoveryPolicy, PREDEFINED_GUARDIANS
from keyweave.network import KeyWeaveNetwork
import time
import base64
import hashlib
import os
import json
import socket
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Helper Functions ---
def print_header(title):
    print("\n" + "="*50)
    print(f"🚀 {title} 🚀")
    print("="*50)

def print_backend(message):
    print(f"\n[BACKEND LOG]... {message}")
    time.sleep(0.5)

# Generate encryption key from PIN
def generate_key_from_pin(pin):
    salt = b'KeyWeaveSalt123'  # Should be unique per installation in production
    return hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 100000, 32)

# AES encryption with PIN-derived key
def encrypt_with_pin(plaintext, pin):
    key = generate_key_from_pin(pin)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad plaintext to multiple of 16 bytes
    pad_len = 16 - (len(plaintext) % 16)
    padded_text = plaintext.encode() + bytes([pad_len] * pad_len)
    
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# AES decryption with PIN-derived key
def decrypt_with_pin(ciphertext, pin):
    try:
        data = base64.b64decode(ciphertext)
        iv = data[:16]
        ciphertext = data[16:]
        key = generate_key_from_pin(pin)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded_plaintext[-1]
        return padded_plaintext[:-pad_len].decode('utf-8')
    except Exception:
        return None

# Create audit record for recovery attempts
def create_audit_record(guardian_ids, outcome, user_id=None):
    # Generate a unique nonce
    nonce = os.urandom(16).hex()
    
    # Get current timestamp
    timestamp = datetime.utcnow().isoformat()
    
    # Get IP address (simplified for demo)
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except:
        ip_address = "127.0.0.1"
    
    # Create record
    record = {
        "guardian_ids": guardian_ids,
        "timestamp": timestamp,
        "user_id": user_id or "default_user",  # In a real system, this would be a unique user identifier
        "outcome": outcome,
        "nonce": nonce,
        "ip_address": ip_address
    }
    
    # Create hash of the record
    record_json = json.dumps(record, sort_keys=True)
    record_hash = hashlib.sha256(record_json.encode()).hexdigest()
    
    # Store the record (in a real system, this would be stored in a secure database)
    audit_log = []
    if os.path.exists("audit_log.json"):
        try:
            with open("audit_log.json", "r") as f:
                audit_log = json.load(f)
        except:
            audit_log = []
    
    audit_log.append({
        "record": record,
        "hash": record_hash
    })
    
    with open("audit_log.json", "w") as f:
        json.dump(audit_log, f, indent=2)
    
    print_backend(f"Audit record created with hash: {record_hash}")
    return record_hash

# --- Main Program ---
def main_interactive_loop():
    my_secret_string = None
    guardians = PREDEFINED_GUARDIANS.copy()
    policy = None
    network = None
    is_setup_complete = False
    # State variables for backup PIN
    backup_set = False
    backup_secret_encrypted = None
    # User identifier (in a real system, this would be a proper user ID)
    user_id = f"user_{int(time.time())}"
    
    # Track recovery attempts
    recovery_attempts = 0
    last_attempt_time = 0
    recovery_frozen_until = 0

    while True:
        print("\n--- KeyWeave Interactive Menu ---")
        print("1. [SETUP] Create a secret and set up Guardian escrow")
        print("2. [RECOVERY] Attempt to recover the secret")
        print("3. [REGISTER] Add a new Guardian")
        print("4. [AUDIT] View audit log")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            print_header("Setting Up KeyWeave Escrow")
            secret_input = input("Enter an alphanumeric secret (e.g., a password or key): ")
            my_secret_string = secret_input if secret_input else "MyP@ssw0rd!_123"
            secret_as_int = int.from_bytes(my_secret_string.encode('utf-8'), 'big')
            print_backend(f"User's secret '{my_secret_string}' encoded to a large integer.")
            
            # Backup PIN setup
            print("\n--- Backup PIN Setup ---")
            set_pin = input("Would you like to set a backup PIN? (y/n): ").lower()
            if set_pin == 'y':
                while True:
                    pin1 = input("Set a secure backup PIN (min 8 characters): ")
                    if len(pin1) < 8:
                        print("PIN must be at least 8 characters")
                        continue
                    pin2 = input("Confirm backup PIN: ")
                    if pin1 == pin2:
                        # Encrypt secret with strong AES encryption
                        backup_secret_encrypted = encrypt_with_pin(my_secret_string, pin1)
                        backup_set = True
                        print("✅ Backup PIN set successfully")
                        break
                    else:
                        print("PINs do not match. Try again")
            else:
                print("Skipping backup PIN setup")

            print_backend("Defining the Recovery Policy with runtime threshold...")
            policy = RecoveryPolicy([g.did for g in guardians])

            print_backend("Initializing the KeyWeave Network and distributing shards...")
            network = KeyWeaveNetwork()
            success = network.setup_escrow(secret_as_int, policy, guardians)
            
            if success:
                is_setup_complete = True
                print("\n✅ Setup is complete! The secret is now protected by the Guardians.")
            else:
                print("\n❌ Setup failed. Please ensure IPFS daemon is running.")

        elif choice == '2':
            current_time = time.time()
            
            # Check if recovery is frozen
            if current_time < recovery_frozen_until:
                remaining_time = recovery_frozen_until - current_time
                print(f"\n❌ Recovery is frozen for {int(remaining_time)} more seconds due to too many failed attempts.")
                continue
                
            if not is_setup_complete:
                print("\n❌ Please run Setup (Option 1) before attempting recovery.")
                continue

            print_header("Initiating Secret Recovery")
            print("Available Guardians:")
            for i, g in enumerate(guardians):
                print(f"  {i+1}: {g.name}")
            print(f"  {len(guardians)+1}: Mallory (An UNKNOWN Impostor)")

            selection = input("Enter the numbers of participating guardians, separated by commas (e.g., 1,3,5): ")
            participating_guardians = []
            guardian_ids = []

            try:
                indices = [int(s.strip()) - 1 for s in selection.split(',')]
                print_backend(f"User selected guardians with numbers: {[i+1 for i in indices]}")

                for i in indices:
                    if 0 <= i < len(guardians):
                        participating_guardians.append(guardians[i])
                        guardian_ids.append(guardians[i].did)
                    elif i == len(guardians):
                        print_backend("An impostor is attempting to join the recovery!")
                        impostor = Guardian("Mallory (Impostor)")
                        impostor.shard = (99, 99999)
                        impostor.commitment = "invalid"
                        participating_guardians.append(impostor)
                        guardian_ids.append("impostor_did")
                    else:
                        print(f"Warning: Guardian number {i+1} is invalid and will be ignored.")
            except ValueError:
                print("\n❌ Invalid input. Please enter numbers separated by commas.")
                continue

            print_backend("Starting the recovery protocol with the selected participants...")
            recovered_secret_as_int = network.initiate_recovery(participating_guardians, policy)

            if recovered_secret_as_int is not None:
                num_bytes = (recovered_secret_as_int.bit_length() + 7) // 8
                recovered_secret_string = recovered_secret_as_int.to_bytes(num_bytes, 'big').decode('utf-8')

                print("\n" + "="*50)
                print(f"🎉 RECOVERY SUCCEEDED! 🎉")
                print(f"Reconstructed Secret: {recovered_secret_string}")
                print("="*50)

                if recovered_secret_string == my_secret_string:
                    print("✅ The reconstructed secret matches the original!")
                    # Create audit record for successful recovery
                    create_audit_record(guardian_ids, "success", user_id)
                    # Reset attempt counter on success
                    recovery_attempts = 0
                else:
                    print("🔥 CRITICAL ERROR: Reconstructed secret does NOT match the original!")
                    # Create audit record for failed recovery
                    create_audit_record(guardian_ids, "failure_mismatch", user_id)
                    # Increment attempt counter
                    recovery_attempts += 1
            else:
                print("\n" + "="*50)
                print("🛡️ RECOVERY FAILED. 🛡️")
                print("The secret remains secure. This is the expected outcome if the policy conditions were not met.")
                print("="*50)
                
                # Create audit record for failed recovery
                create_audit_record(guardian_ids, "failure_policy", user_id)
                
                # Increment attempt counter
                recovery_attempts += 1
                
                # Backup PIN recovery option
                if backup_set:
                    use_backup = input("Recovery failed. Would you like to use your backup PIN? (y/n): ").lower()
                    if use_backup == 'y':
                        pin_attempt = input("Enter your backup PIN: ")
                        try:
                            decrypted_secret = decrypt_with_pin(backup_secret_encrypted, pin_attempt)
                            if decrypted_secret:
                                print("\n" + "="*50)
                                print(f"🎉 BACKUP RECOVERY SUCCEEDED! 🎉")
                                print(f"Recovered Secret: {decrypted_secret}")
                                print("="*50)
                                if decrypted_secret == my_secret_string:
                                    print("✅ The reconstructed secret matches the original!")
                                    # Create audit record for successful backup recovery
                                    create_audit_record(["backup_pin"], "success", user_id)
                                    # Reset attempt counter on success
                                    recovery_attempts = 0
                                else:
                                    print("🔥 CRITICAL ERROR: Reconstructed secret does NOT match the original!")
                                    # Create audit record for failed backup recovery
                                    create_audit_record(["backup_pin"], "failure_mismatch", user_id)
                                    # Increment attempt counter
                                    recovery_attempts += 1
                            else:
                                print("❌ Backup recovery failed: Invalid PIN or corrupted data")
                                # Create audit record for failed backup recovery
                                create_audit_record(["backup_pin"], "failure_invalid_pin", user_id)
                                # Increment attempt counter
                                recovery_attempts += 1
                        except Exception as e:
                            print(f"❌ Backup recovery failed: {e}")
                            # Create audit record for failed backup recovery
                            create_audit_record(["backup_pin"], "failure_exception", user_id)
                            # Increment attempt counter
                            recovery_attempts += 1
                    else:
                        print("Backup PIN not used.")
                else:
                    print("No backup PIN was set during setup. Cannot use backup recovery.")
            
            # Check if we've reached the attempt limit
            if recovery_attempts >= 3:
                recovery_frozen_until = time.time() + 10  # Freeze for 10 seconds
                print(f"\n❌ Too many failed attempts. Recovery is now frozen for 10 seconds.")
                recovery_attempts = 0  # Reset counter after freezing

        elif choice == '3':
            print_header("Registering New Guardian")
            guardian_name = input("Enter the new Guardian's name: ")
            new_guardian = Guardian(guardian_name)
            guardians.append(new_guardian)
            print(f"✅ Guardian '{new_guardian.name}' added at runtime with DID: {new_guardian.did[:15]}...")

        elif choice == '4':
            print_header("Audit Log")
            if os.path.exists("audit_log.json"):
                try:
                    with open("audit_log.json", "r") as f:
                        audit_log = json.load(f)
                    
                    if not audit_log:
                        print("No audit records found.")
                    else:
                        for i, record in enumerate(audit_log):
                            print(f"\nRecord {i+1}:")
                            print(f"  Hash: {record['hash']}")
                            print(f"  Timestamp: {record['record']['timestamp']}")
                            print(f"  User ID: {record['record']['user_id']}")
                            print(f"  Outcome: {record['record']['outcome']}")
                            print(f"  Guardian IDs: {', '.join([gid[:10] + '...' for gid in record['record']['guardian_ids']])}")
                            print(f"  IP Address: {record['record']['ip_address']}")
                except Exception as e:
                    print(f"Error reading audit log: {e}")
            else:
                print("No audit records found.")

        elif choice == '5':
            print("\nExiting KeyWeave demonstration. Goodbye! 👋")
            break

        else:
            print("\nInvalid choice. Please enter 1, 2, 3, 4, or 5.")

if __name__ == "__main__":
    main_interactive_loop()