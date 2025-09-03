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
from shutil import which

# Constants
VERSION = 0.2
AGE_REPO_URL = "https://github.com/FiloSottile/age"
STORE_DIR = Path("store")
USERS_CONFIG_FILE = Path("users.json")
USER_SECRET_FILE = Path("user-secret.age")
USER_SECRET_ENC_FILE = Path("user-secret.age.enc")
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


def exec_bytes(command: list[str], input_data: bytes | None = None) -> bytes:
    """Execute a command and return stdout as bytes, raise error if returncode != 0."""
    process = subprocess.run(command, input=input_data, capture_output=True)

    if process.returncode != 0:
        cmd_str = " ".join(command)
        raise RuntimeError(f"Command '{cmd_str}' failed: {process.stderr.decode()}")

    return process.stdout


def age(args: list[str], input_data: bytes | None = None) -> bytes:
    """Run the `age` binary with given args via exec_bytes and return stdout bytes.

    Preserves stdin (when input_data is None) so passphrase prompts work.
    """
    try:
        return exec_bytes(["age", *args], input_data)
    except FileNotFoundError:
        print(
            f"Error: 'age' is not installed. Please visit {AGE_REPO_URL} for installation instructions."
        )
        sys.exit(1)


def age_keygen(args: list[str], input_data: bytes | None = None) -> bytes:
    """Run the `age-keygen` binary with given args via exec_bytes and return stdout bytes."""
    try:
        return exec_bytes(["age-keygen", *args], input_data)
    except FileNotFoundError:
        print(
            f"Error: 'age-keygen' is not installed. Please visit {AGE_REPO_URL} for installation instructions."
        )
        sys.exit(1)


def age_keygen_generate() -> tuple[str, str]:
    """Generate an age keypair and return (private_key, public_key)."""
    result = age_keygen([]).decode()
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


def age_encrypt_recipients_to_file(
    data: bytes, recipients: list[str], output_path: Path
) -> None:
    """Encrypt bytes using age recipients and write directly to output_path."""
    cmd_list: list[str] = []
    for recipient in recipients:
        cmd_list.extend(["-r", recipient])
    cmd_list.extend(["-o", str(output_path)])
    _ = age(cmd_list, data)


def age_keygen_public_from_private(private_key: str) -> str:
    """Get age public key from private key."""
    return age_keygen(["-y"], private_key.encode()).decode().strip()


def age_decrypt_file_with_identity(
    encrypted_file_path: Path, private_key: str
) -> bytes:
    """Decrypt file using age identity (private key provided via stdin). Returns bytes."""
    return age(["-d", "-i", "-", str(encrypted_file_path)], private_key.encode())


def age_encrypt_file_with_passphrase(input_path: Path, output_path: Path) -> None:
    """Encrypt a file with a passphrase, prompting on TTY; writes to output_path.

    Uses exec_bytes to preserve TTY stdin for passphrase prompts, and ignores stdout.
    """
    # exec_bytes captures stdout/stderr, but does not override stdin when input_data is None.
    # This allows age to prompt on the controlling TTY for the passphrase.
    _ = age(["-p", "-o", str(output_path), str(input_path)], None)


def age_decrypt_file_with_passphrase(input_path: Path) -> str:
    """Decrypt a passphrase-encrypted file, prompting on TTY, return plaintext (str)."""
    out = age(["-d", str(input_path)], None)
    return out.decode().strip()


def check_unencrypted_user_secret_permissions() -> bool:
    """Check if unencrypted user secret file has secure permissions.

    Returns False if permissions are too open (readable by group or others).
    Returns True if permissions are secure (owner-only).
    """
    if not USER_SECRET_FILE.exists():
        return True  # No file means no permission issue

    file_stat = USER_SECRET_FILE.stat()
    return not (file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH))


def read_user_secret() -> str:
    """Read user secret from unencrypted or encrypted storage.

    - If `user-secret.age` exists, enforce secure permissions and return its contents.
    - Else if `user-secret.age.enc` exists, decrypt it using `age` and return the plaintext.
    - Else, instruct the user to run `init-user`.
    """
    if USER_SECRET_FILE.exists():
        # Warn if using unencrypted secret file
        print(
            f"Warning: Using unencrypted user secret at {USER_SECRET_FILE}. Consider using an encrypted secret (user-secret.age.enc)."
        )

        # Check permissions
        if not check_unencrypted_user_secret_permissions():
            print(
                f"Error: User secret file {USER_SECRET_FILE} is readable by group or others"
            )
            print(f"Fix with: chmod 600 {USER_SECRET_FILE}")
            sys.exit(1)

        # Read and return the private key
        with open(USER_SECRET_FILE, "r") as f:
            return f.read().strip()

    if USER_SECRET_ENC_FILE.exists():
        # Decrypt using age, allowing it to prompt for passphrase via stdin/tty.
        try:
            return age_decrypt_file_with_passphrase(USER_SECRET_ENC_FILE)
        except RuntimeError as e:
            print(f"Error: Failed to decrypt {USER_SECRET_ENC_FILE}: {e}")
            sys.exit(1)

    print(f"Error: No user secret found. Run 'init-user' to create one.")
    sys.exit(1)


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
    user_public_key = age_keygen_public_from_private(user_private_key)

    # Check if user's public key is in users.json
    users_config = load_users_config()
    if user_public_key not in users_config.values():
        print("Error: Access denied")
        sys.exit(1)

    # Decrypt master private key using user's private key (text output)
    return (
        age_decrypt_file_with_identity(MASTER_KEY_FILE, user_private_key)
        .decode()
        .strip()
    )


def get_all_users() -> list[str]:
    """Get list of all users with access to secrets."""
    users_config = load_users_config()
    return list(users_config.keys())


def re_encrypt_all_secrets(old_master_private_key: str, new_master_public_key: str):
    """Re-encrypt all secrets in the store with a new master key."""
    print("Re-encrypting secrets with new master key...")
    for secret_file in STORE_DIR.glob("*.enc"):
        try:
            # Decrypt with old master key
            content = age_decrypt_file_with_identity(
                secret_file, old_master_private_key
            )

            # Re-encrypt with new master public key directly to the same file
            age_encrypt_recipients_to_file(
                content, [new_master_public_key], secret_file
            )

            print(f"Re-encrypted: {secret_file}")
        except RuntimeError as e:
            print(f"Warning: Failed to re-encrypt {secret_file}: {e}")


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
    user_public_key = age_keygen_public_from_private(user_private_key)

    # Generate master keypair
    master_private_key, _ = age_keygen_generate()

    # Encrypt master private key with user's public key and write to file
    age_encrypt_recipients_to_file(
        master_private_key.encode(), [user_public_key], MASTER_KEY_FILE
    )

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
    master_public_key = age_keygen_public_from_private(master_private_key)

    # Read file content as bytes
    with open(file_path, "rb") as f:
        content = f.read()

    # Prepare output path
    secret_file = STORE_DIR / f"{file_path.name}.enc"

    # Check if encrypted file already exists
    while secret_file.exists():
        response = (
            input(
                f"File {secret_file} already exists in store. Overwrite, rename, or skip? [y/N/r]: "
            )
            .strip()
            .lower()
        )
        if response == "y":
            break  # Proceed to overwrite
        elif response == "r":
            new_name = input(f"Enter new filename (without .enc): ").strip()
            if not new_name:
                print("Error: No filename provided, skipping")
                return
            secret_file = STORE_DIR / f"{new_name}.enc"
            if secret_file.exists():
                print(f"Error: File {secret_file} already exists, try again")
                continue
        else:  # Default to 'n' or any other input
            print(f"Skipping {file_path}: not overwritten")
            return

    # Encrypt file with master public key directly to secret_file
    age_encrypt_recipients_to_file(content, [master_public_key], secret_file)

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
        content = age_decrypt_file_with_identity(secret_file, master_private_key)
        # Write bytes to stdout to support binary files
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.flush()
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
    age_encrypt_recipients_to_file(
        master_private_key.encode(), current_recipients, MASTER_KEY_FILE
    )

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
        new_master_private_key, new_master_public_key = age_keygen_generate()

        # Re-encrypt all secrets with new master key
        print("Regenerating master key and re-encrypting secrets...")
        re_encrypt_all_secrets(old_master_private_key, new_master_public_key)

        # Encrypt new master private key for remaining users
        remaining_recipients = list(users_config.values())
        age_encrypt_recipients_to_file(
            new_master_private_key.encode(), remaining_recipients, MASTER_KEY_FILE
        )
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
    new_master_private_key, new_master_public_key = age_keygen_generate()

    # Get current users
    users_config = load_users_config()

    if not users_config:
        print("No users found")
        return

    # Re-encrypt all secrets with new master key
    re_encrypt_all_secrets(old_master_private_key, new_master_public_key)

    # Re-encrypt new master private key for all users
    print("Re-encrypting master private key for users...")
    user_public_keys = list(users_config.values())
    age_encrypt_recipients_to_file(
        new_master_private_key.encode(), user_public_keys, MASTER_KEY_FILE
    )

    print("Master keypair rotation complete")


def cmd_init_user(unencrypted: bool):
    """Initialize user by generating age keypair.

    - If `--unencrypted` is provided, save the private key to `user-secret.age` with 600 perms.
    - Otherwise, encrypt the private key with a passphrase and save as `user-secret.age.enc`.
    """

    # Prevent overwriting existing secrets
    if USER_SECRET_FILE.exists() or USER_SECRET_ENC_FILE.exists():
        which = USER_SECRET_FILE if USER_SECRET_FILE.exists() else USER_SECRET_ENC_FILE
        print(f"Error: User secret already exists at {which}")
        sys.exit(1)

    # Generate age keypair for the user
    user_private_key, user_public_key = age_keygen_generate()

    if unencrypted:
        # Save user's private key to user-secret.age
        with open(USER_SECRET_FILE, "w") as f:
            f.write(user_private_key)

        # Set secure permissions (owner read/write only)
        os.chmod(USER_SECRET_FILE, stat.S_IRUSR | stat.S_IWUSR)

        print("User initialization complete (unencrypted)")
        print(f"Age public key: {user_public_key}")
        print(f"Age private key saved to: {USER_SECRET_FILE}")
        print("Private key file permissions set to 600 (owner read/write only)")
        return

    # Encrypted user secret: write plaintext to user-secret.age and then encrypt with age -p
    try:
        # Write plaintext private key to user-secret.age
        with open(USER_SECRET_FILE, "w") as f:
            f.write(user_private_key)
        os.chmod(USER_SECRET_FILE, stat.S_IRUSR | stat.S_IWUSR)

        # Run age with passphrase, reading plaintext from user-secret.age.
        # Allow age to access the TTY for passphrase entry by not overriding stdin.
        age_encrypt_file_with_passphrase(USER_SECRET_FILE, USER_SECRET_ENC_FILE)

        print("User initialization complete (encrypted)")
        print(f"Age public key: {user_public_key}")
        print(f"Encrypted private key saved to: {USER_SECRET_ENC_FILE}")
        print(
            f"Note: Plaintext private key also present at {USER_SECRET_FILE} (permissions 600)."
        )
    except FileNotFoundError as e:
        print(f"Error: Required command not found: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_show_pubkey():
    """Show the user's age public key."""
    # Read user's private key with error handling and permission checks
    user_private_key = read_user_secret()

    # Get user's public key from private key
    try:
        public_key = age_keygen_public_from_private(user_private_key)
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


def cmd_doctor():
    """Run health checks and print a bullet list of results."""
    results: list[tuple[str, str]] = []

    # Check age and age-keygen presence without exiting
    if which("age") is None:
        results.append(("ERROR", "'age' not found in PATH"))
    else:
        results.append(("OK", "'age' is installed"))
    if which("age-keygen") is None:
        results.append(("ERROR", "'age-keygen' not found in PATH"))
    else:
        results.append(("OK", "'age-keygen' is installed"))

    # Secret encryption status and permissions
    if USER_SECRET_FILE.exists():
        results.append(
            ("WARN", f"Unencrypted user secret present at {USER_SECRET_FILE}")
        )
        if not check_unencrypted_user_secret_permissions():
            results.append(
                (
                    "ERROR",
                    f"Permissions for {USER_SECRET_FILE} are too open; run: chmod 600 {USER_SECRET_FILE}",
                )
            )
        else:
            results.append(
                ("OK", f"Permissions for {USER_SECRET_FILE} are 600 (owner-only)")
            )
    elif USER_SECRET_ENC_FILE.exists():
        results.append(("OK", f"User secret is encrypted ({USER_SECRET_ENC_FILE})"))
    else:
        results.append(("WARN", "No user secret found (run 'init-user')"))

    # Attempt to load current user's private key (may prompt if encrypted)
    user_private_key: str | None = None
    try:
        if USER_SECRET_FILE.exists():
            with open(USER_SECRET_FILE, "r") as f:
                user_private_key = f.read().strip()
        elif USER_SECRET_ENC_FILE.exists():
            user_private_key = age_decrypt_file_with_passphrase(USER_SECRET_ENC_FILE)
    except Exception as e:
        results.append(("WARN", f"Failed to load user private key: {e}"))

    # Check users list membership
    try:
        users_cfg = load_users_config()
        if user_private_key:
            pub = age_keygen_public_from_private(user_private_key)
            if pub in users_cfg.values():
                results.append(("OK", "Current user is listed in users.json"))
            else:
                results.append(("WARN", "Current user is not listed in users.json"))
        else:
            results.append(("WARN", "Skipped users.json check (no user key loaded)"))
    except Exception as e:
        results.append(("WARN", f"Failed to check users.json: {e}"))

    # Check master key decryption
    if MASTER_KEY_FILE.exists():
        if user_private_key:
            try:
                _ = age_decrypt_file_with_identity(MASTER_KEY_FILE, user_private_key)
                results.append(("OK", "Can decrypt master key"))
            except Exception as e:
                results.append(("WARN", f"Failed to decrypt master key: {e}"))
        else:
            results.append(
                ("WARN", "Skipped master key decrypt check (no user key loaded)")
            )
    else:
        results.append(
            (
                "WARN",
                f"Master key file not found at {MASTER_KEY_FILE} (not bootstrapped?)",
            )
        )

    # Print results
    for level, msg in results:
        print(f"- {level}: {msg}")


def cmd_migrate_encrypt_user_secret():
    """Encrypt plaintext user secret to user-secret.age.enc and delete plaintext."""
    # Preconditions
    if not USER_SECRET_FILE.exists():
        print(f"Error: Plaintext secret {USER_SECRET_FILE} not found.")
        sys.exit(1)

    # Run age -p to produce encrypted file
    try:
        age_encrypt_file_with_passphrase(USER_SECRET_FILE, USER_SECRET_ENC_FILE)
    except RuntimeError as e:
        print(f"Error: Failed to encrypt user secret: {e}")
        sys.exit(1)

    # Verify encrypted file now exists, then remove plaintext
    if not USER_SECRET_ENC_FILE.exists():
        print(f"Error: Failed to create {USER_SECRET_ENC_FILE}")
        sys.exit(1)

    try:
        USER_SECRET_FILE.unlink()
    except OSError as e:
        print(f"Error: Encrypted file created but failed to delete plaintext: {e}")
        sys.exit(1)

    print(
        f"Migrated user secret to {USER_SECRET_ENC_FILE} and removed {USER_SECRET_FILE}"
    )


def cmd_version():
    """Print the current version."""
    print(f"age-store v{VERSION}")
    print("Copyright (c) 2025 Farseen")
    print("License: MIT")


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
    init_user_parser = subparsers.add_parser(
        "init-user", help="Initialize user by generating age keypair"
    )
    init_user_parser.add_argument(
        "--unencrypted",
        action="store_true",
        help="Initialize with an unencrypted private key file",
    )
    subparsers.add_parser("show-pubkey", help="Show user's age public key")

    # Version command
    subparsers.add_parser("version", help="Print the current version")

    # Doctor command
    subparsers.add_parser("doctor", help="Run health checks and show results")

    # List files command
    subparsers.add_parser("ls", help="List all available files")

    # View file command
    view_file_parser = subparsers.add_parser(
        "view", help="View a file from the secret store"
    )
    view_file_parser.add_argument(
        "file", help="Name of the file to view (without .enc extension)"
    )

    # Add file command
    add_file_parser = subparsers.add_parser(
        "add", help="Add a file to the secret store"
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

    # Migrate commands
    migrate_parser = subparsers.add_parser(
        "migrate",
        help="Migration helpers for existing installations.",
    )
    migrate_subparsers = migrate_parser.add_subparsers(
        dest="migrate_command",
        metavar="MIGRATE_COMMAND",
        title=None,  # type: ignore
        description=None,
    )
    migrate_subparsers.add_parser(
        "encrypt-user-secret",
        help=(
            "Encrypt plaintext user secret (user-secret.age) to user-secret.age.enc with a "
            "passphrase, then remove the plaintext."
        ),
    )

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
        elif args.command == "add":
            cmd_add_file(args.file)
        elif args.command == "view":
            cmd_view_file(args.file)
        elif args.command == "ls":
            cmd_list_store()
        elif args.command == "init-user":
            cmd_init_user(args.unencrypted)
        elif args.command == "show-pubkey":
            cmd_show_pubkey()
        elif args.command == "migrate":
            if not args.migrate_command:
                migrate_parser.print_help()
                sys.exit(1)
            if args.migrate_command == "encrypt-user-secret":
                cmd_migrate_encrypt_user_secret()
        elif args.command == "version":
            cmd_version()
        elif args.command == "doctor":
            cmd_doctor()
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
