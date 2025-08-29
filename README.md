# Age Store

A simple, secure secret management system built on the proven [age encryption](https://age-encryption.org/) standard. Age Store makes it easy to share encrypted files across teams using familiar command-line tools.

## Why Age Store?

- **Built on Standards**: Uses the widely-adopted `age` encryption tool under the hood
- **Dead Simple**: Just a single Python script with an intuitive CLI
- **No Dependencies**: Only requires Python 3.6+ and the standard `age` tool
- **Team-Friendly**: Easy multi-user access control with public key sharing
- **Secure by Design**: Leverages age's proven cryptography and file format

## Quick Setup (30 seconds)

```bash
# 1. Download age-store
curl -O https://raw.githubusercontent.com/itsfarseen/age-store/main/age-store.py
chmod +x age-store.py

# 2. Initialize yourself as a user
./age-store.py init-user

# 3. Bootstrap the store (first time only)
./age-store.py admin bootstrap myusername

# 4. Add your first secret
./age-store.py add-file my-secret-file

# 5. View it anytime
./age-store.py view-file my-secret-file
```

That's it! Your secrets are now encrypted and ready to share with your team.

## Prerequisites

- Python 3.6+
- [age](https://age-encryption.org/) (`apt install age` or `brew install age`)

## Everyday Usage

```bash
# Add any file to the encrypted store
./age-store.py add-file config.json
./age-store.py add-file .env

# View files instantly 
./age-store.py view-file config.json
./age-store.py list-files

# Share access with teammates
./age-store.py admin add-user alice age1abc123...
./age-store.py admin list-users
```

## How It Works

Age Store uses a master keypair to encrypt all secrets. This master private key is encrypted with the age public keys of all authorized users. To access a secret, users decrypt the master key with their personal age private key, then decrypt the secret files.

When users are added, the master key is re-encrypted for all current users plus the new one. When users are removed, a new master keypair is generated, all secrets are re-encrypted, and the new master key is shared only with remaining users.

## Team Collaboration

```bash
# Alice shares her public key
alice$ ./age-store.py show-pubkey
Age public key: age1alice123...

# Bob adds Alice to the store
bob$ ./age-store.py admin add-user alice age1alice123...

# Now Alice can access all secrets
alice$ ./age-store.py view-file shared-config.json
```

## Commands Reference

### Daily Use
- `add-file <file>` - Encrypt and store any file
- `view-file <name>` - Decrypt and view a stored file  
- `list-files` - See all your encrypted files

### Setup & Team Management
- `init-user` - Generate your age keypair (run once)
- `show-pubkey` - Display your public key to share with teammates
- `admin bootstrap <username>` - Initialize the store (first time only)
- `admin add-user <name> <pubkey>` - Give someone access
- `admin remove-user <name>` - Revoke access
- `admin list-users` - See who has access

### Security Operations  
- `admin rotate-master-key` - Rotate master key and re-encrypt everything

## File Layout

```
your-project/
├── age-store.py          # The tool (single file)
├── user-secret.age       # Your private key
├── master-key.age.enc   # Shared master key (encrypted)
├── users.json           # Team roster
└── store/               # Your encrypted files
    ├── config.json.enc
    ├── secrets.env.enc
    └── ssh-key.enc
```

## Why Not [Other Tool]?

- **vs HashiCorp Vault**: No server setup, no complex policies - just files
- **vs pass**: Built for teams from day one, not retrofitted
- **vs 1Password CLI**: No subscription, open source, standard crypto
- **vs git-crypt**: Works with any files, not just git repos
- **vs SOPS**: SOPS is a complex dependency; Age Store is a single Python script you can copy into your project

Age Store gives you Vault-like team secret sharing with the simplicity of a single script.

## Configuration

Age Store can be configured by modifying the constants at the top of the script:

```python
# Constants
STORE_DIR = Path("store")
USERS_CONFIG_FILE = Path("users.json")
USER_SECRET_FILE = Path("user-secret.age")
MASTER_KEY_FILE = Path("master-key.age.enc")
```

- `STORE_DIR`: Directory where encrypted files are stored (default: `store/`)
- `USERS_CONFIG_FILE`: File mapping usernames to public keys (default: `users.json`)
- `USER_SECRET_FILE`: Current user's private key file (default: `user-secret.age`)
- `MASTER_KEY_FILE`: Encrypted master key file (default: `master-key.age.enc`)

Simply edit these paths in the script to customize file locations for your project structure.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
