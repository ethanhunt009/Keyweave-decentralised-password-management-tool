from keyweave.entities import Guardian, RecoveryPolicy
from keyweave.network import KeyWeaveNetwork
import time

# --- Helper Functions for UI ---

def print_header(title):
    """Prints a formatted header."""
    print("\n" + "="*50)
    print(f"🚀 {title} 🚀")
    print("="*50)

def print_backend(message):
    """Simulates a backend log message for clarity."""
    print(f"\n[BACKEND LOG]... {message}")
    time.sleep(0.5) # A small delay for dramatic effect

# --- Main Interactive Loop ---

def main_interactive_loop():
    """Runs the main interactive menu for the demonstration."""
    # Global state for the demo
    my_secret_string = None
    guardians = []
    policy = None
    network = None
    is_setup_complete = False

    while True:
        print("\n--- KeyWeave Interactive Menu ---")
        print("1. [SETUP] Create a secret and set up Guardian escrow")
        print("2. [RECOVERY] Attempt to recover the secret")
        print("3. Exit")
        
        choice = input("Enter your choice: ")

        if choice == '1':
            print_header("Setting Up KeyWeave Escrow")
            secret_input = input("Enter an alphanumeric secret (e.g., a password or key): ")
            if not secret_input:
                print("No secret entered. Using a default secret.")
                my_secret_string = "MyP@ssw0rd!_123"
            else:
                my_secret_string = secret_input
            
            # --- ENCODING: Convert the string secret to an integer for the crypto ---
            # The Shamir's algorithm works on numbers, so we encode the string.
            secret_as_int = int.from_bytes(my_secret_string.encode('utf-8'), 'big')
            print_backend(f"User's secret '{my_secret_string}' encoded to a large integer.")
            
            print_backend("Initializing Guardians...")
            guardians = [Guardian("Alice (Family)"), Guardian("Bob (Friend)"), Guardian("Charlie (Lawyer)"), Guardian("David (Friend)"), Guardian("Eve (Colleague)")]
            for g in guardians:
                print(f"  -> Guardian '{g.name}' created with DID: {g.did[:15]}...")
            
            print_backend("Defining the Recovery Policy (3 of 5 required)...")
            policy = RecoveryPolicy(threshold=3, guardian_dids=[g.did for g in guardians])
            
            print_backend("Initializing the KeyWeave Network and distributing shards...")
            network = KeyWeaveNetwork()
            # We pass the integer version of the secret to the network
            network.setup_escrow(secret_as_int, policy, guardians)
            
            is_setup_complete = True
            print("\n✅ Setup is complete! The secret is now protected by the Guardians.")

        elif choice == '2':
            if not is_setup_complete:
                print("\n❌ Please run Setup (Option 1) before attempting recovery.")
                continue

            print_header("Initiating Secret Recovery")
            print("Available Guardians:")
            for i, g in enumerate(guardians):
                print(f"  {i+1}: {g.name}")
            print("  6: Mallory (An UNKNOWN Impostor)")

            selection = input("Enter the numbers of participating guardians, separated by commas (e.g., 1,3,5): ")
            
            participating_guardians = []
            try:
                indices = [int(s.strip())-1 for s in selection.split(',')]
                print_backend(f"User selected guardians with numbers: {[i+1 for i in indices]}")

                for i in indices:
                    if 0 <= i < len(guardians):
                        participating_guardians.append(guardians[i])
                    elif i == 5: # The impostor
                        print_backend("An impostor is attempting to join the recovery!")
                        impostor = Guardian("Mallory (Impostor)")
                        impostor.receive_shard((99, 99999)) # Fake shard
                        participating_guardians.append(impostor)
                    else:
                        print(f"Warning: Guardian number {i+1} is invalid and will be ignored.")
            except ValueError:
                print("\n❌ Invalid input. Please enter numbers separated by commas.")
                continue
                
            print_backend("Starting the recovery protocol with the selected participants...")
            recovered_secret_as_int = network.initiate_recovery(participating_guardians, policy)
            
            if recovered_secret_as_int is not None:
                # --- DECODING: Convert the recovered integer back to a string ---
                num_bytes = (recovered_secret_as_int.bit_length() + 7) // 8
                recovered_secret_string = recovered_secret_as_int.to_bytes(num_bytes, 'big').decode('utf-8')

                print("\n" + "="*50)
                print(f"🎉 RECOVERY SUCCEEDED! 🎉")
                print(f"Reconstructed Secret: {recovered_secret_string}")
                print("="*50)

                if recovered_secret_string == my_secret_string:
                    print("✅ The reconstructed secret matches the original!")
                else:
                    print("🔥 CRITICAL ERROR: Reconstructed secret does NOT match the original!")
            else:
                print("\n" + "="*50)
                print(f"🛡️ RECOVERY FAILED. 🛡️")
                print("The secret remains secure. This is the expected outcome if the policy conditions were not met.")
                print("="*50)

        elif choice == '3':
            print("\nExiting KeyWeave demonstration. Goodbye! 👋")
            break
        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main_interactive_loop()
