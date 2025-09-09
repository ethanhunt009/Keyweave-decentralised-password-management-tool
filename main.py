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
    print(f"{title}")
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
def create_audit_record(guardian_ids, outcome, user_id=None, account_name=None):
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
        "user_id": user_id or "default_user",
        "account_name": account_name or "all_accounts",
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

# User authentication functions
def hash_password(password):
    """Hash a password for storing."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + key

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:32]
    stored_key = stored_password[32:]
    key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return key == stored_key

def user_signup():
    """Handle user registration"""
    print_header("User Sign Up")
    
    username = input("Choose a username: ")
    
    # Check if user already exists
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            users = json.load(f)
        if username in users:
            print("Username already exists. Please choose a different one.")
            return None
    else:
        users = {}
    
    password = input("Choose a password: ")
    confirm_password = input("Confirm password: ")
    
    if password != confirm_password:
        print("Passwords do not match.")
        return None
    
    # Hash and store the password
    hashed_password = hash_password(password)
    users[username] = hashed_password.hex()
    
    with open("users.json", "w") as f:
        json.dump(users, f)
    
    # Create user directory for storing data
    user_dir = f"user_{username}"
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    
    # Create a guardian profile for this user
    guardian = Guardian(username)  # This will generate DID and keys
    
    # Now save the guardian to global guardians.json if it doesn't exist
    guardians = {}
    if os.path.exists("guardians.json"):
        with open("guardians.json", "r") as f:
            guardians = json.load(f)
    
    # Only add if not already exists
    if username not in guardians:
        guardians[username] = {
            "name": guardian.name,
            "did": guardian.did,
            "public_key": guardian.public_key
        }
        with open("guardians.json", "w") as f:
            json.dump(guardians, f, indent=2)
    
    # Save the private key in the user's data
    user_data = load_user_data(username)
    user_data["guardian_private_key"] = guardian.get_private_key_bytes()
    save_user_data(username, user_data)
    
    print("User registration successful! Guardian profile created.")
    
    # Now select guardians and set threshold
    select_guardians_and_threshold(username)
    
    return username

def select_guardians_and_threshold(username):
    """Allow user to select guardians from existing users and set threshold."""
    print_header("Select Guardians and Set Threshold")
    
    # Load global guardians
    if not os.path.exists("guardians.json"):
        print("No guardians available yet. Please ask other users to sign up first.")
        return False

    with open("guardians.json", "r") as f:
        all_guardians = json.load(f)

    # Remove current user from the list
    if username in all_guardians:
        del all_guardians[username]

    if not all_guardians:
        print("No other guardians available. You can add guardians later.")
        return False

    # Convert to list for indexing
    guardian_list = list(all_guardians.items())
    
    while True:
        # Search functionality
        search_term = input("\nEnter search term to filter guardians (or press enter to see all): ")
        if search_term:
            filtered_guardians = []
            for uname, g in guardian_list:
                if search_term.lower() in uname.lower() or search_term.lower() in g['name'].lower():
                    filtered_guardians.append((uname, g))
            display_list = filtered_guardians
            if not display_list:
                print("No guardians match the search term.")
                continue
        else:
            display_list = guardian_list

        # Display list of guardians
        print("\nAvailable Guardians:")
        for idx, (uname, g) in enumerate(display_list):
            print(f"{idx+1}. {g['name']} (Username: {uname}, DID: {g['did'][:10]}...)")

        # Select guardians
        selected_guardians = []
        try:
            choice = input("\nEnter the numbers of guardians to select, separated by commas (e.g., 1,3,5): ")
            if not choice.strip():
                print("No selection made. Please try again.")
                continue
                
            indices = [int(idx.strip()) - 1 for idx in choice.split(',')]
            for idx in indices:
                if 0 <= idx < len(display_list):
                    uname, g = display_list[idx]
                    selected_guardians.append({
                        "name": g['name'],
                        "did": g['did'],
                        "public_key": g['public_key']
                    })
                else:
                    print(f"Invalid index: {idx+1}")
            
            if selected_guardians:
                break
            else:
                print("No valid guardians selected. Please try again.")
        except ValueError:
            print("Invalid input. Please enter numbers separated by commas.")

    # Set threshold
    while True:
        try:
            threshold = int(input(f"\nEnter recovery threshold (1-{len(selected_guardians)}): "))
            if 1 <= threshold <= len(selected_guardians):
                break
            else:
                print(f"Threshold must be between 1 and {len(selected_guardians)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # Load user data and update with selected guardians and threshold
    user_data = load_user_data(username)
    user_data["guardians"] = selected_guardians
    user_data["threshold"] = threshold
    save_user_data(username, user_data)

    print(f"\nSelected {len(selected_guardians)} guardians and threshold set to {threshold}.")
    return True

def initialize_predefined_guardians():
    """Initialize the predefined guardians and save them to guardians.json"""
    guardians = {}
    
    # Check if guardians.json already exists
    if os.path.exists("guardians.json"):
        with open("guardians.json", "r") as f:
            guardians = json.load(f)
    
    # Add predefined guardians if they don't exist
    from keyweave.entities import PREDEFINED_GUARDIANS
    for guardian in PREDEFINED_GUARDIANS:
        if guardian.name not in guardians:
            guardians[guardian.name] = {
                "name": guardian.name,
                "did": guardian.did,
                "public_key": guardian.public_key
            }
    
    # Save to file
    with open("guardians.json", "w") as f:
        json.dump(guardians, f, indent=2)
    
    print("Predefined guardians initialized.")

def user_login():
    """Handle user login"""
    print_header("User Login")
    
    if not os.path.exists("users.json"):
        print("No users registered yet. Please sign up first.")
        return None
    
    with open("users.json", "r") as f:
        users = json.load(f)
    
    username = input("Username: ")
    password = input("Password: ")
    
    if username not in users:
        print("User not found.")
        return None
    
    stored_password = bytes.fromhex(users[username])
    if verify_password(stored_password, password):
        print("Login successful!")
        return username
    else:
        print("Invalid password.")
        return None

# User data management functions
def load_user_data(username):
    """Load user data from file"""
    user_dir = f"user_{username}"
    data_file = os.path.join(user_dir, "data.json")
    
    if os.path.exists(data_file):
        with open(data_file, "r") as f:
            return json.load(f)
    return {
        "accounts": {},
        "guardians": [],
        "threshold": 0,  # New field for threshold
        "backup_set": False,
        "backup_secret_encrypted": None,
        "backup_pin": None,
        "policy": None,
        "is_setup_complete": False,
        "guardian_private_key": None  # New field for user's own guardian private key
    }


def save_user_data(username, data):
    """Save user data to file"""
    user_dir = f"user_{username}"
    data_file = os.path.join(user_dir, "data.json")
    
    with open(data_file, "w") as f:
        json.dump(data, f)

def user_recovery():
    """Handle account recovery without login"""
    print_header("Account Recovery")
    
    if not os.path.exists("users.json"):
        print("No users registered yet. Please sign up first.")
        return None
    
    with open("users.json", "r") as f:
        users = json.load(f)
    
    username = input("Enter your username: ")
    
    if username not in users:
        print("User not found.")
        return None
    
    # Load user data
    user_data = load_user_data(username)
    
    # Extract data
    accounts = user_data.get("accounts", {})
    guardians_data = user_data.get("guardians", [])
    backup_set = user_data.get("backup_set", False)
    backup_secret_encrypted = user_data.get("backup_secret_encrypted", None)
    backup_pin = user_data.get("backup_pin", None)
    policy_data = user_data.get("policy", None)
    is_setup_complete = user_data.get("is_setup_complete", False)
    
    # Recreate guardians from data
    guardians = []
    for g_data in guardians_data:
        guardian = Guardian(g_data["name"])
        guardian.did = g_data["did"]
        guardian.public_key = g_data["public_key"]
        guardian.shards = g_data.get("shards", {})
        guardian.commitments = g_data.get("commitments", {})
        guardian.cids = g_data.get("cids", {})
        guardians.append(guardian)
    
    # Recreate policy from data
    policy = None
    if policy_data:
        policy = RecoveryPolicy([])
        policy.threshold = policy_data["threshold"]
        policy.num_guardians = policy_data["num_guardians"]
        policy.authorized_dids = set(policy_data["authorized_dids"])
    
    network = KeyWeaveNetwork()
    
    # Track recovery attempts
    recovery_attempts = 0
    recovery_frozen_until = 0
    
    # Check if setup is complete
    if not is_setup_complete:
        print("No recovery setup found for this user. Please set up guardians first.")
        return None

    # Start recovery process
    current_time = time.time()
    
    # Check if recovery is frozen
    if current_time < recovery_frozen_until:
        remaining_time = recovery_frozen_until - current_time
        print(f"\nRecovery is frozen for {int(remaining_time)} more seconds due to too many failed attempts.")
        return None

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
        print("\nInvalid input. Please enter numbers separated by commas.")
        return None

    print_backend("Starting the recovery protocol with the selected participants...")
    recovered_secret_as_int = network.initiate_recovery(participating_guardians, policy)

    if recovered_secret_as_int is not None:
        # Calculate the number of bytes needed to represent the integer
        num_bytes = (recovered_secret_as_int.bit_length() + 7) // 8
        
        # Convert to bytes and handle potential padding issues
        recovered_bytes = recovered_secret_as_int.to_bytes(num_bytes, 'big')
        
        # Try to decode as UTF-8
        try:
            recovered_secret_string = recovered_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # If UTF-8 decoding fails, try adding a padding byte
            recovered_bytes = recovered_secret_as_int.to_bytes(num_bytes + 1, 'big')
            try:
                recovered_secret_string = recovered_bytes.decode('utf-8')
            except UnicodeDecodeError:
                print("Failed to decode recovered secret. The data may be corrupted.")
                # Create audit record for failed recovery
                create_audit_record(guardian_ids, "failure_corrupted", username, "all_accounts")
                # Increment attempt counter
                recovery_attempts += 1
                return None
        
        try:
            # Try to parse the recovered data as JSON (account dictionary)
            recovered_accounts = json.loads(recovered_secret_string)
            
            print("\n" + "="*50)
            print(f"RECOVERY SUCCEEDED!")
            print("Recovered Accounts:")
            
            for account_name, (username_acc, password_acc) in recovered_accounts.items():
                print(f"  {account_name}: {username_acc} / {password_acc}")
            
            print("="*50)
            
            # Update local accounts with recovered data
            accounts.update(recovered_accounts)
            
            # Create audit record for successful recovery
            create_audit_record(guardian_ids, "success", username, "all_accounts")
            
            # Reset attempt counter on success
            recovery_attempts = 0
            
            # Save the recovered data
            user_data["accounts"] = accounts
            save_user_data(username, user_data)
            
            print("Your accounts have been recovered successfully!")
            return username
        except json.JSONDecodeError:
            print("\nRecovered data is not valid JSON. It may be corrupted.")
            # Create audit record for failed recovery
            create_audit_record(guardian_ids, "failure_corrupted", username, "all_accounts")
            # Increment attempt counter
            recovery_attempts += 1
            return None
    else:
        print("\n" + "="*50)
        print("🛡️ RECOVERY FAILED. 🛡️")
        print("Access remains secure. This is the expected outcome if the policy conditions were not met.")
        print("="*50)
        
        # Create audit record for failed recovery
        create_audit_record(guardian_ids, "failure_policy", username, "all_accounts")
        
        # Increment attempt counter
        recovery_attempts += 1
        
        # Backup PIN recovery option
        if backup_set:
            use_backup = input("Recovery failed. Would you like to use your backup PIN? (y/n): ").lower()
            if use_backup == 'y':
                pin_attempt = input("Enter your backup PIN: ")
                try:
                    decrypted_data = decrypt_with_pin(backup_secret_encrypted, pin_attempt)
                    if decrypted_data:
                        try:
                            # Try to parse the decrypted data as JSON
                            recovered_accounts = json.loads(decrypted_data)
                            
                            print("\n" + "="*50)
                            print(f"🎉 BACKUP RECOVERY SUCCEEDED! 🎉")
                            print("Recovered Accounts:")
                            
                            for account_name, (username_acc, password_acc) in recovered_accounts.items():
                                print(f"  {account_name}: {username_acc} / {password_acc}")
                            
                            print("="*50)
                            
                            # Update local accounts with recovered data
                            accounts.update(recovered_accounts)
                            
                            # Create audit record for successful backup recovery
                            create_audit_record(["backup_pin"], "success", username, "all_accounts")
                            
                            # Reset attempt counter on success
                            recovery_attempts = 0
                            
                            # Save the recovered data
                            user_data["accounts"] = accounts
                            save_user_data(username, user_data)
                            
                            print("Your accounts have been recovered successfully using your backup PIN!")
                            return username
                        except json.JSONDecodeError:
                            print("Backup data is corrupted.")
                            # Create audit record for failed backup recovery
                            create_audit_record(["backup_pin"], "failure_corrupted", username, "all_accounts")
                            # Increment attempt counter
                            recovery_attempts += 1
                    else:
                        print("Backup recovery failed: Invalid PIN")
                        # Create audit record for failed backup recovery
                        create_audit_record(["backup_pin"], "failure_invalid_pin", username, "all_accounts")
                        # Increment attempt counter
                        recovery_attempts += 1
                except Exception as e:
                    print(f"Backup recovery failed: {e}")
                    # Create audit record for failed backup recovery
                    create_audit_record(["backup_pin"], "failure_exception", username, "all_accounts")
                    # Increment attempt counter
                    recovery_attempts += 1
            else:
                print("Backup PIN not used.")
        else:
            print("No backup PIN was set during setup. Cannot use backup recovery.")
    
    # Check if we've reached the attempt limit
    if recovery_attempts >= 3:
        recovery_frozen_until = time.time() + 10  # Freeze for 10 seconds
        print(f"\nToo many failed attempts. Recovery is now frozen for 10 seconds.")
        recovery_attempts = 0  # Reset counter after freezing
    
    return None

# --- Main Program ---
def main_interactive_loop(username):
    # Load user data
    user_data = load_user_data(username)
    
    # Extract data
    accounts = user_data.get("accounts", {})
    guardians_data = user_data.get("guardians", [])
    threshold = user_data.get("threshold", 0)  # Get threshold from user data
    backup_set = user_data.get("backup_set", False)
    backup_secret_encrypted = user_data.get("backup_secret_encrypted", None)
    backup_pin = user_data.get("backup_pin", None)
    policy_data = user_data.get("policy", None)
    is_setup_complete = user_data.get("is_setup_complete", False)
    
    # Recreate guardians from data
    guardians = []
    for g_data in guardians_data:
        guardian = Guardian(g_data["name"])
        guardian.did = g_data["did"]
        guardian.public_key = g_data["public_key"]
        guardian.private_key = None  # Set to None, will load from user data when needed
        guardian.shards = g_data.get("shards", {})
        guardian.commitments = g_data.get("commitments", {})
        guardian.cids = g_data.get("cids", {})
        guardians.append(guardian)
    
    # Recreate policy from data - use stored threshold
    policy = None
    if policy_data:
        policy = RecoveryPolicy([])
        policy.threshold = policy_data["threshold"]
        policy.num_guardians = policy_data["num_guardians"]
        policy.authorized_dids = set(policy_data["authorized_dids"])
    else:
        # If policy not set, create from stored threshold and guardians
        if guardians and threshold > 0:
            policy = RecoveryPolicy([g.did for g in guardians])
            policy.threshold = threshold  # Override the threshold set in RecoveryPolicy
            policy.num_guardians = len(guardians)
            policy.authorized_dids = set([g.did for g in guardians])
    
    network = KeyWeaveNetwork()
    
    # Track recovery attempts
    recovery_attempts = 0
    recovery_frozen_until = 0

    while True:
        print(f"\n--- KeyWeave Password Manager (User: {username}) ---")
        print("1. [SETUP] Set PIN")
        print("2. [ADD] Add a new account to store")
        print("3. [VIEW] View stored accounts (requires recovery)")
        print("4. [RECOVERY] Recover access to accounts")
        print("5. [REGISTER] Add a new Guardian")
        print("6. [AUDIT] View audit log")
        print("7. [LOGOUT] Log out")
        print("8. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            print_header("Initializing KeyWeave Password Manager")
            
            # Check if there are any guardians
            if not guardians:
                print("No guardians available. Please add guardians first (Option 5).")
                continue
            
            # Use the stored threshold from user data
            if threshold == 0:
                print("Threshold not set. Please set threshold during signup or later.")
                continue

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
                        backup_set = True
                        backup_pin = pin1
                        print("Backup PIN set successfully")
                        break
                    else:
                        print("PINs do not match. Try again")
            else:
                print("Skipping backup PIN setup")

            print_backend("Defining the Recovery Policy with stored threshold...")
            # Create policy using stored threshold (pass it as parameter)
            policy = RecoveryPolicy([g.did for g in guardians], threshold)
            policy.num_guardians = len(guardians)
            policy.authorized_dids = set([g.did for g in guardians])

            print_backend("Initializing the KeyWeave Network...")
            network = KeyWeaveNetwork()
            
            # Create a test secret to initialize the guardians
            test_secret = int.from_bytes("test_initialization".encode('utf-8'), 'big')
            success = network.setup_escrow(test_secret, policy, guardians)
            
            if success:
                is_setup_complete = True
                print("\nPassword manager initialized! You can now add accounts.")
            else:
                print("\nSetup failed. Please check if IPFS is running and try again.")

        elif choice == '2':
            if not is_setup_complete:
                print("\nPlease initialize the password manager (Option 1) first.")
                continue
                
            print_header("Adding New Account")
            account_name = input("Enter account name (e.g., 'Gmail', 'GitHub'): ")
            username_acc = input("Enter username: ")
            password_acc = input("Enter password: ")
            
            # Store the account
            accounts[account_name] = (username_acc, password_acc)
            print(f"Account '{account_name}' stored successfully.")
            
            # Convert accounts to a single string for encryption
            accounts_json = json.dumps(accounts)
            
            # Encrypt with backup PIN if set
            if backup_set:
                backup_secret_encrypted = encrypt_with_pin(accounts_json, backup_pin)
                print("Accounts encrypted with backup PIN.")

            # Split and distribute the accounts data
            secret_as_int = int.from_bytes(accounts_json.encode('utf-8'), 'big')
            success = network.setup_escrow(secret_as_int, policy, guardians, account_name)
            
            if success:
                print(f"Account '{account_name}' secured with Guardians.")
            else:
                print(f"Failed to secure account '{account_name}' with Guardians.")

        elif choice == '3':
            if not accounts:
                print("\nNo accounts stored yet. Add accounts first.")
                continue
                
            print_header("Stored Accounts")
            for i, account_name in enumerate(accounts.keys(), 1):
                print(f"{i}. {account_name}")
            
            try:
                selection = int(input("\nSelect account to view (0 to cancel): "))
                if selection == 0:
                    continue
                account_name = list(accounts.keys())[selection-1]
                username_acc, password_acc = accounts[account_name]
                print(f"\nAccount: {account_name}")
                print(f"Username: {username_acc}")
                print(f"Password: {password_acc}")
            except (ValueError, IndexError):
                print("Invalid selection.")

        elif choice == '4':
            current_time = time.time()
            
            # Check if recovery is frozen
            if current_time < recovery_frozen_until:
                remaining_time = recovery_frozen_until - current_time
                print(f"\nRecovery is frozen for {int(remaining_time)} more seconds due to too many failed attempts.")
                continue
            print(f"setup complete : {is_setup_complete}")
            if not is_setup_complete:
                print("\nPlease initialize the password manager (Option 1) first.")
                continue

            print_header("Recovering Access to Accounts")
            print("Available Guardians:")
            for i, g in enumerate(guardians):
                print(f"  {i+1}: {g.name}")
            print(f"  {len(guardians)+1}: Mallory (An UNKNOWN Impostor)")

            selection = input("Enter the numbers of participating guardians, separated by commas (e.e., 1,3,5): ")
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
                print("\nInvalid input. Please enter numbers separated by commas.")
                continue

            print_backend("Starting the recovery protocol with the selected participants...")
            recovered_secret_as_int = network.initiate_recovery(participating_guardians, policy)

            if recovered_secret_as_int is not None:
                # Calculate the number of bytes needed to represent the integer
                num_bytes = (recovered_secret_as_int.bit_length() + 7) // 8
                
                # Convert to bytes and handle potential padding issues
                recovered_bytes = recovered_secret_as_int.to_bytes(num_bytes, 'big')
                
                # Try to decode as UTF-8
                try:
                    recovered_secret_string = recovered_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    # If UTF-8 decoding fails, try adding a padding byte
                    recovered_bytes = recovered_secret_as_int.to_bytes(num_bytes + 1, 'big')
                    try:
                        recovered_secret_string = recovered_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        print("Failed to decode recovered secret. The data may be corrupted.")
                        # Create audit record for failed recovery
                        create_audit_record(guardian_ids, "failure_corrupted", username, "all_accounts")
                        # Increment attempt counter
                        recovery_attempts += 1
                        continue
                
                try:
                    # Try to parse the recovered data as JSON (account dictionary)
                    recovered_accounts = json.loads(recovered_secret_string)
                    
                    print("\n" + "="*50)
                    print(f"RECOVERY SUCCEEDED!")
                    print("Recovered Accounts:")
                    
                    for account_name, (username_acc, password_acc) in recovered_accounts.items():
                        print(f"  {account_name}: {username_acc} / {password_acc}")
                    
                    print("="*50)
                    
                    # Update local accounts with recovered data
                    accounts.update(recovered_accounts)
                    
                    # Create audit record for successful recovery
                    create_audit_record(guardian_ids, "success", username, "all_accounts")
                    
                    # Reset attempt counter on success
                    recovery_attempts = 0
                except json.JSONDecodeError:
                    print("\nRecovered data is not valid JSON. It may be corrupted.")
                    # Create audit record for failed recovery
                    create_audit_record(guardian_ids, "failure_corrupted", username, "all_accounts")
                    # Increment attempt counter
                    recovery_attempts += 1
            else:
                print("\n" + "="*50)
                print("RECOVERY FAILED.xxxxxxxxxxxxxxxxxxxxxxxxxxx")
                print("Access remains secure. This is the expected outcome if the policy conditions were not met.")
                print("="*50)
                
                # Create audit record for failed recovery
                create_audit_record(guardian_ids, "failure_policy", username, "all_accounts")
                
                # Increment attempt counter
                recovery_attempts += 1
                
                # Backup PIN recovery option
                if backup_set:
                    use_backup = input("Recovery failed. Would you like to use your backup PIN? (y/n): ").lower()
                    if use_backup == 'y':
                        pin_attempt = input("Enter your backup PIN: ")
                        try:
                            decrypted_data = decrypt_with_pin(backup_secret_encrypted, pin_attempt)
                            if decrypted_data:
                                try:
                                    # Try to parse the decrypted data as JSON
                                    recovered_accounts = json.loads(decrypted_data)
                                    
                                    print("\n" + "="*50)
                                    print(f"BACKUP RECOVERY SUCCEEDED")
                                    print("Recovered Accounts:")
                                    
                                    for account_name, (username_acc, password_acc) in recovered_accounts.items():
                                        print(f"  {account_name}: {username_acc} / {password_acc}")
                                    
                                    print("="*50)
                                    
                                    # Update local accounts with recovered data
                                    accounts.update(recovered_accounts)
                                    
                                    # Create audit record for successful backup recovery
                                    create_audit_record(["backup_pin"], "success", username, "all_accounts")
                                    
                                    # Reset attempt counter on success
                                    recovery_attempts = 0
                                except json.JSONDecodeError:
                                    print("Backup data is corrupted.")
                                    # Create audit record for failed backup recovery
                                    create_audit_record(["backup_pin"], "failure_corrupted", username, "all_accounts")
                                    # Increment attempt counter
                                    recovery_attempts += 1
                            else:
                                print("Backup recovery failed: Invalid PIN")
                                # Create audit record for failed backup recovery
                                create_audit_record(["backup_pin"], "failure_invalid_pin", username, "all_accounts")
                                # Increment attempt counter
                                recovery_attempts += 1
                        except Exception as e:
                            print(f"Backup recovery failed: {e}")
                            # Create audit record for failed backup recovery
                            create_audit_record(["backup_pin"], "failure_exception", username, "all_accounts")
                            # Increment attempt counter
                            recovery_attempts += 1
                    else:
                        print("Backup PIN not used.")
                else:
                    print("No backup PIN was set during setup. Cannot use backup recovery.")
            
            # Check if we've reached the attempt limit
            if recovery_attempts >= 3:
                recovery_frozen_until = time.time() + 10  # Freeze for 10 seconds
                print(f"\nToo many failed attempts. Recovery is now frozen for 10 seconds.")
                recovery_attempts = 0  # Reset counter after freezing

        elif choice == '5':
            print_header("Registering New Guardian")
            guardian_name = input("Enter the new Guardian's name: ")
            new_guardian = Guardian(guardian_name)
            guardians.append(new_guardian)
            print(f"Guardian '{new_guardian.name}' added at runtime with DID: {new_guardian.did[:15]}...")

        elif choice == '6':
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
                            print(f"  Account: {record['record']['account_name']}")
                            print(f"  Outcome: {record['record']['outcome']}")
                            print(f"  Guardian IDs: {', '.join([gid[:10] + '...' for gid in record['record']['guardian_ids']])}")
                            print(f"  IP Address: {record['record']['ip_address']}")
                except Exception as e:
                    print(f"Error reading audit log: {e}")
            else:
                print("No audit records found.")

        elif choice == '7':
            # Save user data before logout
            user_data = {
                "accounts": accounts,
                "guardians": [{
                    "name": g.name,
                    "did": g.did,
                    "public_key": g.public_key,
                    "shards": g.shards,
                    "commitments": g.commitments,
                    "cids": g.cids
                } for g in guardians],
                "threshold": threshold,
                "backup_set": backup_set,
                "backup_secret_encrypted": backup_secret_encrypted,
                "backup_pin": backup_pin,
                "policy": {
                    "threshold": policy.threshold if policy else None,
                    "num_guardians": policy.num_guardians if policy else None,
                    "authorized_dids": list(policy.authorized_dids) if policy else []
                },
                "is_setup_complete": is_setup_complete
            }
            
            save_user_data(username, user_data)
            print(f"\nLogged out successfully. Goodbye, {username}! 👋")
            return

        elif choice == '8':
            # Save user data before exit
            user_data = {
                "accounts": accounts,
                "guardians": [{
                    "name": g.name,
                    "did": g.did,
                    "public_key": g.public_key,
                    "shards": g.shards,
                    "commitments": g.commitments,
                    "cids": g.cids
                } for g in guardians],
                "threshold": threshold,
                "backup_set": backup_set,
                "backup_secret_encrypted": backup_secret_encrypted,
                "backup_pin": backup_pin,
                "policy": {
                    "threshold": policy.threshold if policy else None,
                    "num_guardians": policy.num_guardians if policy else None,
                    "authorized_dids": list(policy.authorized_dids) if policy else []
                },
                "is_setup_complete": is_setup_complete
            }
            
            save_user_data(username, user_data)
            print("\nExiting KeyWeave Password Manager.")
            break

        else:
            print("\nInvalid choice. Please enter 1, 2, 3, 4, 5, 6, 7, or 8.")

def main():
    """Main entry point with authentication"""
    initialize_predefined_guardians()
    while True:
        print_header("KeyWeave Password Manager")
        print("1. Sign Up")
        print("2. Sign In")
        print("3. Recover Account")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            username = user_signup()
            if username:
                main_interactive_loop(username)
                
        elif choice == '2':
            username = user_login()
            if username:
                main_interactive_loop(username)
                
        elif choice == '3':
            username = user_recovery()
            if username:
                print(f"Recovery successful! Logging in as {username}...")
                main_interactive_loop(username)
                
        elif choice == '4':
            print("\nExiting KeyWeave Password Manager.")
            break
            
        else:
            print("\nInvalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()