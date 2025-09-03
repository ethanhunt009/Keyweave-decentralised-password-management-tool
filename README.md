# KeyWeave Password Manager

A decentralized password manager that uses Shamir's Secret Sharing and IPFS for secure, distributed storage of credentials. KeyWeave allows users to store passwords securely and recover them through a network of trusted guardians.

## Overview

KeyWeave is a next-generation password manager that eliminates single points of failure by distributing encrypted password shards across multiple guardians. Unlike traditional password managers that rely on a master password or centralized recovery, KeyWeave uses decentralized technology to ensure your passwords remain secure yet recoverable.

## Features

- **Decentralized Storage**: Passwords are encrypted, split into shards, and distributed to guardians using IPFS
- **Guardian-Based Recovery**: Recover access with help from trusted contacts (guardians)
- **Multi-Factor Recovery**: Set recovery thresholds (e.g., 3 of 5 guardians required)
- **Backup PIN Option**: Additional recovery method using a memorizable PIN
- **Audit Logging**: Cryptographic audit trails for all recovery attempts
- **Multi-User Support**: Support for multiple users with isolated data
- **No Single Point of Failure**: Eliminates central authority for recovery

## Technology Stack

- **Cryptography**: AES-256 encryption, RSA for guardian communication, Shamir's Secret Sharing
- **Decentralized Storage**: IPFS (InterPlanetary File System)
- **Programming Language**: Python 3
- **Key Libraries**: cryptography, requests, hashlib

## Installation

### Prerequisites

- Python 3.7 or higher
- IPFS daemon (for decentralized storage)
- pip (Python package manager)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd keyweave
   ```

2. **Start IPFS daemon**
   ```bash
   ipfs daemon
   ```

3. **Run the application**
   ```bash
   python main.py
   ```

## Usage

### Initial Setup

1. **Create an account**: Choose a username and password
2. **Add guardians**: Register trusted contacts as guardians
3. **Set recovery policy**: Define how many guardians are needed for recovery
4. **Set backup PIN**: Optionally create a backup PIN for emergency recovery
5. **Add accounts**: Store usernames and passwords for your various accounts

### Account Recovery

If you lose access to your password manager:

1. **Select recovery option** from the main menu
2. **Choose participating guardians** from your trusted network
3. **Complete the recovery process** by meeting the threshold of guardian approvals
4. **Alternative recovery**: Use your backup PIN if guardians are unavailable

### Guardian Responsibilities

As a guardian, you will:

- Receive encrypted shards of others' password data
- Store these shards securely using your private key
- Participate in recovery processes when requested
- Verify your identity through cryptographic proofs

## Security Architecture

### Encryption Scheme

1. **User Data Encryption**: AES-256 with PIN-derived keys
2. **Shard Encryption**: RSA encryption with guardian-specific public keys
3. **Secret Sharing**: Shamir's Secret Sharing algorithm with configurable thresholds

### Storage Approach

1. **Local Storage**: User credentials and metadata stored locally
2. **IPFS Storage**: Encrypted shards distributed across the IPFS network
3. **Guardian Storage**: Each guardian stores shards encrypted with their public key

### Recovery Process

1. **Guardian Authentication**: Cryptographic proof of shard possession
2. **Shard Reconstruction**: Lagrange interpolation to reconstruct the secret
3. **Data Decryption**: Recovered data decrypted with the reconstructed key

## Module Structure

- **main.py**: Primary application entry point
- **auth.py**: User authentication functions (signup/login)
- **recovery.py**: Account recovery system
- **entities.py**: Data models (Guardian, RecoveryPolicy)
- **network.py**: IPFS integration and network operations
- **crypto.py**: Cryptographic functions (Shamir's Secret Sharing)
- **utils.py**: Utility functions and helpers
- **user_session.py**: User session management

## Security Considerations

- Always run IPFS on a secure, private network
- Choose guardians who understand security responsibilities
- Use strong, unique passwords for your accounts
- Keep your backup PIN secure and memorable
- Regularly review audit logs for suspicious activity

## Limitations

- Requires IPFS daemon to be running for full functionality
- Guardian participation requires technical understanding
- Initial setup process is more complex than traditional password managers

## Future Enhancements

- Mobile application for guardian approvals
- Web-based guardian interface
- Biometric authentication support
- Cross-platform synchronization
- Enhanced audit and reporting features

## Contributing

Contributions to KeyWeave are welcome. Please ensure that any changes maintain or improve the security properties of the system and include appropriate tests.

## License

KeyWeave is released under the MIT License. See LICENSE file for details.

## Support

For support questions or security concerns, please open an issue in the project repository or contact the development team directly.

---

**Important**: KeyWeave is a demonstration of decentralized password management concepts. Users should conduct their own security assessment before relying on it for sensitive credentials.
