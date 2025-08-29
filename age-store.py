#!/usr/bin/env python3
"""
Age Store - Secret Management System
"""

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

# Constants
STORE_DIR = Path("store")
USERS_CONFIG_FILE = Path("users.json")
USER_SECRET_FILE = Path("user-secret.age")
MASTER_KEY_FILE = Path("master-key.age.enc")


def ensure_directories():
    """Create necessary directories if they don't exist."""
    STORE_DIR.mkdir(exist_ok=True)


def load_users_config() -> dict:
    """Load users configuration from users.json."""
    if not USERS_CONFIG_FILE.exists():
        return {}

    try:
        with open(USERS_CONFIG_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {USERS_CONFIG_FILE}: {e}")
        sys.exit(1)
    except IOError as e:
        print(f"Error: Cannot read {USERS_CONFIG_FILE}: {e}")
        sys.exit(1)


def save_users_config(config: dict):
    """Save users configuration to users.json."""
    with open(USERS_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def exec(command: list[str], input_data: str | None = None) -> str:
    """Execute a command and return stdout, raise error if returncode != 0."""
    process = subprocess.run(command, input=input_data, text=True, capture_output=True)

    if process.returncode != 0:
        cmd_str = " ".join(command)
        raise RuntimeError(f"Command '{cmd_str}' failed: {process.stderr}")

    return process.stdout


def exec_bytes(command: list[str], input_data: bytes | None = None) -> bytes:
    """Execute a command and return stdout as bytes, raise error if returncode != 0."""
    process = subprocess.run(command, input=input_data, capture_output=True)

    if process.returncode != 0:
        cmd_str = " ".join(command)
        raise RuntimeError(f"Command '{cmd_str}' failed: {process.stderr.decode()}")

    return process.stdout


def generate_age_keypair() -> tuple[str, str]:
    """Generate an age keypair and return (private_key, public_key)."""
    result = exec(["age-keygen"])
    lines = result.strip().split("\n")

    # Find the public key comment and private key
    public_key = None
    private_key = None

    for line in lines:
        if line.startswith("# public key: "):
            public_key = line.replace("# public key: ", "").strip()
        elif line.startswith("AGE-SECRET-KEY-"):
            private_key = line.strip()

    if not public_key or not private_key:
        raise RuntimeError("Failed to parse age-keygen output")

    return private_key, public_key


def encrypt_with_age_recipients(data: str, recipients: list[str]) -> bytes:
    """Encrypt data using age recipients and return encrypted content."""
    cmd_list = ["age"]
    for recipient in recipients:
        cmd_list.extend(["-r", recipient])

    return exec_bytes(cmd_list, data.encode())


def get_public_key_from_private(private_key: str) -> str:
    """Get age public key from private key."""
    return exec(["age-keygen", "-y"], private_key).strip()


def decrypt_with_age_key(encrypted_file_path: Path, private_key: str) -> str:
    """Decrypt data from file using age private key."""
    return exec(["age", "-d", "-i", "-", str(encrypted_file_path)], private_key)


def read_user_secret() -> str:
    """Read user secret file with proper error handling and permission checks."""
    if not USER_SECRET_FILE.exists():
        print(
            f"Error: User secret file {USER_SECRET_FILE} not found. Run 'init-user' first."
        )
        sys.exit(1)

    # Check permissions
    file_stat = USER_SECRET_FILE.stat()
    permissions = stat.filemode(file_stat.st_mode)

    # Check if group or others have read permissions
    if file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH):
        print(
            f"Error: User secret file {USER_SECRET_FILE} is readable by group or others"
        )
        print(f"Current permissions: {permissions}")
        print(f"Fix with: chmod 600 {USER_SECRET_FILE}")
        sys.exit(1)

    # Read and return the private key
    with open(USER_SECRET_FILE, "r") as f:
        return f.read().strip()


def get_master_private_key() -> str:
    """Get the master private key for the current user."""
    if not MASTER_KEY_FILE.exists():
        print(
            f"Error: Master password file {MASTER_KEY_FILE} not found. Run 'admin bootstrap' first."
        )
        sys.exit(1)

    # Read user's private key with error handling and permission checks
    user_private_key = read_user_secret()

    # Get user's public key from private key
    user_public_key = get_public_key_from_private(user_private_key)

    # Check if user's public key is in users.json
    users_config = load_users_config()
    if user_public_key not in users_config.values():
        print("Error: Access denied")
        sys.exit(1)

    # Decrypt master private key using user's private key
    return decrypt_with_age_key(MASTER_KEY_FILE, user_private_key).strip()


def get_all_users() -> list[str]:
    """Get list of all users with access to secrets."""
    users_config = load_users_config()
    return list(users_config.keys())


# Commands


def cmd_bootstrap(initial_user: str):
    """Bootstrap the secret store with initial master keypair."""
    print(f"Bootstrapping secret store for user: {initial_user}")

    ensure_directories()

    # Check if already bootstrapped
    if MASTER_KEY_FILE.exists():
        print("Error: Secret store already bootstrapped.")
        sys.exit(1)

    # Read user secret and get public key from private key
    user_private_key = read_user_secret()
    user_public_key = get_public_key_from_private(user_private_key)

    # Generate master keypair
    master_private_key, _ = generate_age_keypair()

    # Encrypt master private key with user's public key
    encrypted_master_key = encrypt_with_age_recipients(
        master_private_key, [user_public_key]
    )

    # Save encrypted master private key to file
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(encrypted_master_key)

    # Create users.json with user mapping
    users_config = {initial_user: user_public_key}
    save_users_config(users_config)

    print(f"Bootstrap complete. Master keypair created for user: {initial_user}")


def cmd_add_file(file_path_str: str):
    """Add a file to the secret store."""
    file_path = Path(file_path_str)

    if not file_path.exists():
        print(f"Error: File {file_path} not found")
        sys.exit(1)

    # Get master private key
    master_private_key = get_master_private_key()

    # Get master public key from private key
    master_public_key = get_public_key_from_private(master_private_key)

    # Read file content
    with open(file_path, "r") as f:
        content = f.read()

    # Encrypt file with master public key
    encrypted_content = encrypt_with_age_recipients(content, [master_public_key])
    secret_file = STORE_DIR / f"{file_path.name}.enc"

    with open(secret_file, "wb") as f:
        f.write(encrypted_content)

    print(f"File {file_path} added to secret store as {secret_file}")


def cmd_view_file(filename: str):
    """View a file from the secret store."""
    secret_file = STORE_DIR / f"{filename}.enc"

    if not secret_file.exists():
        print(f"Error: Secret file {secret_file} not found")
        sys.exit(1)

    # Get master private key
    master_private_key = get_master_private_key()

    # Decrypt and display file
    try:
        content = decrypt_with_age_key(secret_file, master_private_key)
        print(content, end="")  # Don't add extra newline
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_add_user(username: str, age_pubkey: str):
    """Add a user by adding their age public key to the system."""
    # Check if user already exists in users.json
    users_config = load_users_config()

    if username in users_config:
        print(f"Error: User {username} already has access")
        sys.exit(1)

    # Get master private key to verify we have admin access
    master_private_key = get_master_private_key()

    # Get all current user public keys
    current_recipients = list(users_config.values())
    # Add the new user's public key
    current_recipients.append(age_pubkey)

    # Re-encrypt master private key with all recipients (including new user)
    encrypted_master_key = encrypt_with_age_recipients(
        master_private_key, current_recipients
    )

    # Save re-encrypted master private key
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(encrypted_master_key)

    # Add user to users.json
    users_config[username] = age_pubkey
    save_users_config(users_config)

    print(f"User {username} added with access to secrets")


def cmd_remove_user(username: str):
    """Remove a user's access to secrets."""
    # Check if user exists in users.json
    users_config = load_users_config()

    if username not in users_config:
        print(f"Error: User {username} does not have access")
        sys.exit(1)

    # Get old master private key
    old_master_private_key = get_master_private_key()

    # Remove user from users
    del users_config[username]

    if users_config:  # If there are remaining users
        # Generate new master keypair for security
        new_master_private_key, new_master_public_key = generate_age_keypair()

        # Re-encrypt all secrets with new master key
        print("Regenerating master key and re-encrypting secrets...")
        for secret_file in STORE_DIR.glob("*.enc"):
            try:
                # Decrypt with old master key
                content = decrypt_with_age_key(secret_file, old_master_private_key)

                # Re-encrypt with new master public key
                encrypted_content = encrypt_with_age_recipients(
                    content, [new_master_public_key]
                )

                with open(secret_file, "wb") as f:
                    f.write(encrypted_content)

                print(f"Re-encrypted: {secret_file}")
            except RuntimeError as e:
                print(f"Warning: Failed to re-encrypt {secret_file}: {e}")

        # Encrypt new master private key for remaining users
        remaining_recipients = list(users_config.values())
        encrypted_master_key = encrypt_with_age_recipients(
            new_master_private_key, remaining_recipients
        )

        with open(MASTER_KEY_FILE, "wb") as f:
            f.write(encrypted_master_key)
    else:
        # No users left, remove master password file
        MASTER_KEY_FILE.unlink()

    # Update users.json
    save_users_config(users_config)

    print(f"Removed {username}'s access")


def cmd_rotate_master_key():
    """Generate new master keypair and re-encrypt for all users."""
    # Get old master private key
    old_master_private_key = get_master_private_key()

    # Generate new master keypair
    new_master_private_key, new_master_public_key = generate_age_keypair()

    # Get current users
    users_config = load_users_config()

    if not users_config:
        print("No users found")
        return

    # Re-encrypt all secrets with new master key
    print("Re-encrypting secrets with new master key...")
    for secret_file in STORE_DIR.glob("*.enc"):
        try:
            # Decrypt with old master key
            content = decrypt_with_age_key(secret_file, old_master_private_key)

            # Re-encrypt with new master public key
            encrypted_content = encrypt_with_age_recipients(
                content, [new_master_public_key]
            )

            with open(secret_file, "wb") as f:
                f.write(encrypted_content)

            print(f"Re-encrypted: {secret_file}")
        except RuntimeError as e:
            print(f"Warning: Failed to re-encrypt {secret_file}: {e}")

    # Re-encrypt new master private key for all users
    print("Re-encrypting master private key for users...")
    user_public_keys = list(users_config.values())
    encrypted_master_key = encrypt_with_age_recipients(
        new_master_private_key, user_public_keys
    )

    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(encrypted_master_key)

    print("Master keypair rotation complete")


def cmd_init_user():
    """Initialize user by generating age keypair."""

    if USER_SECRET_FILE.exists():
        print(f"Error: User secret file already exists at {USER_SECRET_FILE}")
        sys.exit(1)

    # Generate age keypair for the user
    user_private_key, user_public_key = generate_age_keypair()

    # Save user's private key to user-secret.age
    with open(USER_SECRET_FILE, "w") as f:
        f.write(user_private_key)

    # Set secure permissions (owner read/write only)
    os.chmod(USER_SECRET_FILE, stat.S_IRUSR | stat.S_IWUSR)

    print("User initialization complete")
    print(f"Age public key: {user_public_key}")
    print(f"Age private key saved to: {USER_SECRET_FILE}")
    print(f"Private key file permissions set to 600 (owner read/write only)")


def cmd_show_pubkey():
    """Show the user's age public key."""
    # Read user's private key with error handling and permission checks
    user_private_key = read_user_secret()

    # Get user's public key from private key
    try:
        public_key = get_public_key_from_private(user_private_key)
        print(f"Age public key: {public_key}")
    except RuntimeError as e:
        print(f"Error: Failed to derive public key: {e}")
        sys.exit(1)


def cmd_list_users():
    """List all users with access to secrets."""
    print("Users with access to secrets:")
    users = get_all_users()
    if users:
        for user in sorted(users):
            print(f"  {user}")
    else:
        print("  No users found")


def cmd_list_store():
    """List all available secrets."""
    print("Available secrets:")
    secrets = []
    for secret_file in STORE_DIR.glob("*.enc"):
        secrets.append(secret_file.stem)

    if secrets:
        for secret in sorted(secrets):
            print(f"  {secret}")
    else:
        print("  No secrets found")


def main():
    parser = argparse.ArgumentParser(
        description="Age Store",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
        title=None,  # type: ignore
        description=None,
    )

    # User management commands
    subparsers.add_parser("init-user", help="Initialize user by generating age keypair")
    subparsers.add_parser("show-pubkey", help="Show user's age public key")

    # List files command
    subparsers.add_parser("list-files", help="List all available files")

    # View file command
    view_file_parser = subparsers.add_parser(
        "view-file", help="View a file from the secret store"
    )
    view_file_parser.add_argument(
        "file", help="Name of the file to view (without .enc extension)"
    )

    # Add file command
    add_file_parser = subparsers.add_parser(
        "add-file", help="Add a file to the secret store"
    )
    add_file_parser.add_argument("file", help="Path to the file to add")

    # Admin commands subparser
    admin_parser = subparsers.add_parser("admin", help="Administrative commands")
    admin_subparsers = admin_parser.add_subparsers(
        dest="admin_command",
        metavar="ADMIN_COMMAND",
        title=None,  # type: ignore
        description=None,
    )

    # Bootstrap command
    bootstrap_parser = admin_subparsers.add_parser(
        "bootstrap", help="Initialize the secret store"
    )
    bootstrap_parser.add_argument("initial_user", help="Initial user to bootstrap with")

    # Add user command
    add_user_parser = admin_subparsers.add_parser(
        "add-user", help="Add a user with their age public key"
    )
    add_user_parser.add_argument("username", help="Username to add")
    add_user_parser.add_argument("age_pubkey", help="User's age public key")

    # Remove user command
    remove_user_parser = admin_subparsers.add_parser(
        "remove-user", help="Remove a user's access"
    )
    remove_user_parser.add_argument("username", help="Username to remove")

    # Rotate master key command
    admin_subparsers.add_parser(
        "rotate-master-key",
        help="Generate new master keypair and re-encrypt for all users",
    )

    # List users command
    admin_subparsers.add_parser("list-users", help="List all users with access")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "admin":
            if not args.admin_command:
                admin_parser.print_help()
                sys.exit(1)

            if args.admin_command == "bootstrap":
                cmd_bootstrap(args.initial_user)
            elif args.admin_command == "add-user":
                cmd_add_user(args.username, args.age_pubkey)
            elif args.admin_command == "remove-user":
                cmd_remove_user(args.username)
            elif args.admin_command == "rotate-master-key":
                cmd_rotate_master_key()
            elif args.admin_command == "list-users":
                cmd_list_users()
        elif args.command == "add-file":
            cmd_add_file(args.file)
        elif args.command == "view-file":
            cmd_view_file(args.file)
        elif args.command == "list-files":
            cmd_list_store()
        elif args.command == "init-user":
            cmd_init_user()
        elif args.command == "show-pubkey":
            cmd_show_pubkey()
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
