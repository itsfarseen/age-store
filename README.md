# Age Store

[![CI/CD](https://github.com/itsfarseen/age-store/actions/workflows/ci.yml/badge.svg)](https://github.com/itsfarseen/age-store/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/itsfarseen/age-store)](https://github.com/itsfarseen/age-store/releases/latest)

> **📋 See [CHANGELOG.md](CHANGELOG.md) for version history and migration instructions**

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
./age-store.py add my-secret-file

# 5. View it anytime
./age-store.py view my-secret-file
```

That's it! Your secrets are now encrypted and ready to share with your team.

## Prerequisites

- Python 3.6+
- [age](https://age-encryption.org/) (`apt install age` or `brew install age`)

## Everyday Usage

```bash
# Add any file to the encrypted store
./age-store.py add config.json
./age-store.py add .env

# View files instantly 
./age-store.py view config.json
./age-store.py ls

# Bundle multiple files with size headers
./age-store.py bundle config.json .env secrets.txt

# Launch shell with secrets as environment variables
./age-store.py env-shell app.env

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
alice$ ./age-store.py view shared-config.json
```

## Commands Reference

### Core Commands
- `init-user [--unencrypted]` - Generate your age keypair (run once). By default creates encrypted keypair; use `--unencrypted` for plaintext
- `show-pubkey` - Display your public key to share with teammates
- `version` - Show version information
- `doctor` - Run health checks and diagnostics

### File Operations
- `add <file> [--force]` - Encrypt and store any file. Use `--force` to overwrite existing files
- `view <file>` - Decrypt and view a stored file (specify name without .enc extension)
- `bundle <file1> <file2> ...` - Decrypt and output multiple files with headers showing file sizes in format `-- <size> <filename>`
  ```
  $ ./age-store.py bundle config.json .env
  -- 156 config.json
  {"api_key": "secret123", "db_host": "localhost"}
  
  -- 45 .env
  DATABASE_URL=postgresql://user:pass@localhost/db
  ```
- `env-shell <env_file> [options] [-- <args>...]` - Launch shell with environment variables loaded from secrets
  ```
  # Create env file mapping variables to secret files
  $ echo "API_KEY=api-key.txt" > app.env
  $ echo "DB_PASSWORD=db-pass.txt" >> app.env
  
  # Launch shell with secrets as environment variables (shows prompt)
  $ ./age-store.py env-shell app.env
  (age-store:app) user@host:~$ echo $API_KEY
  
  # Use custom shell and pass arguments
  $ ./age-store.py env-shell app.env --shell /bin/zsh -- -c 'echo $API_KEY'
  
  # Disable prompt modification
  $ ./age-store.py env-shell app.env --no-prompt
  
  # Use custom prompt prefix
  $ ./age-store.py env-shell app.env --custom-prompt "my-app"
  (my-app) user@host:~$ 
  
  # Use hook script for additional environment variables (can set AGE_STORE_PROMPT)
  $ echo '#!/bin/bash\necho "COMPUTED_VAR=computed_value"\necho "AGE_STORE_PROMPT=prod-env"' > hook.sh && chmod +x hook.sh
  $ ./age-store.py env-shell app.env --hook ./hook.sh
  (prod-env) user@host:~$ echo $COMPUTED_VAR $AGE_STORE_ENV
  ```
  
  **Shell Prompt Options:**
  - By default, modifies shell prompt to show environment name: `(age-store:<env-file>) user@host:~$`
  - `--no-prompt`: Disable prompt modification
  - `--custom-prompt <text>`: Use custom prompt prefix instead of default
  - Hook scripts can set `AGE_STORE_PROMPT` environment variable (CLI `--custom-prompt` takes precedence)
  
  **Available Environment Variables:**
  - `AGE_STORE_ENV`: Set to the path of the loaded .env file
  - `AGE_STORE_PROMPT`: Can be set by hook scripts to customize prompt (overridden by `--custom-prompt`)
- `ls` - List all available encrypted files

### Team Management (Admin)
- `admin bootstrap <username>` - Initialize the store with initial user (first time only)
- `admin add-user <username> <age_pubkey>` - Give someone access by adding their public key
- `admin remove-user <username>` - Revoke a user's access
- `admin list-users` - Show all users with access
- `admin rotate-master-key` - Generate new master keypair and re-encrypt for all users

### Migration Tools
- `migrate encrypt-user-secret` - Convert plaintext `user-secret.age` to encrypted `user-secret.age.enc`

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
