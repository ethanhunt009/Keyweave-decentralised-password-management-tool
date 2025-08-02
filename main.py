from keyweave.entities import Guardian, RecoveryPolicy, PREDEFINED_GUARDIANS
from keyweave.network import KeyWeaveNetwork
import time

# --- Helper Functions ---
def print_header(title):
    print("\n" + "="*50)
    print(f"🚀 {title} 🚀")
    print("="*50)

def print_backend(message):
    print(f"\n[BACKEND LOG]... {message}")
    time.sleep(0.5)

# --- Main Program ---
def main_interactive_loop():
    my_secret_string = None
    guardians = PREDEFINED_GUARDIANS.copy()
    policy = None
    network = None
    is_setup_complete = False

    while True:
        print("\n--- KeyWeave Interactive Menu ---")
        print("1. [SETUP] Create a secret and set up Guardian escrow")
        print("2. [RECOVERY] Attempt to recover the secret")
        print("3. [REGISTER] Add a new Guardian")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            print_header("Setting Up KeyWeave Escrow")
            secret_input = input("Enter an alphanumeric secret (e.g., a password or key): ")
            my_secret_string = secret_input if secret_input else "MyP@ssw0rd!_123"
            secret_as_int = int.from_bytes(my_secret_string.encode('utf-8'), 'big')
            print_backend(f"User's secret '{my_secret_string}' encoded to a large integer.")

            print_backend("Defining the Recovery Policy with runtime threshold...")
            policy = RecoveryPolicy([g.did for g in guardians])

            print_backend("Initializing the KeyWeave Network and distributing shards...")
            network = KeyWeaveNetwork()
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
            print(f"  {len(guardians)+1}: Mallory (An UNKNOWN Impostor)")

            selection = input("Enter the numbers of participating guardians, separated by commas (e.g., 1,3,5): ")
            participating_guardians = []

            try:
                indices = [int(s.strip()) - 1 for s in selection.split(',')]
                print_backend(f"User selected guardians with numbers: {[i+1 for i in indices]}")

                for i in indices:
                    if 0 <= i < len(guardians):
                        participating_guardians.append(guardians[i])
                    elif i == len(guardians):
                        print_backend("An impostor is attempting to join the recovery!")
                        impostor = Guardian("Mallory (Impostor)")
                        impostor.shard = (99, 99999)
                        impostor.commitment = "invalid"
                        participating_guardians.append(impostor)
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
                else:
                    print("🔥 CRITICAL ERROR: Reconstructed secret does NOT match the original!")
            else:
                print("\n" + "="*50)
                print("🛡️ RECOVERY FAILED. 🛡️")
                print("The secret remains secure. This is the expected outcome if the policy conditions were not met.")
                print("="*50)

        elif choice == '3':
            print_header("Registering New Guardian")
            guardian_name = input("Enter the new Guardian's name: ")
            new_guardian = Guardian(guardian_name)
            guardians.append(new_guardian)
            print(f"✅ Guardian '{new_guardian.name}' added at runtime with DID: {new_guardian.did[:15]}...")

        elif choice == '4':
            print("\nExiting KeyWeave demonstration. Goodbye! 👋")
            break

        else:
            print("\nInvalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main_interactive_loop()
