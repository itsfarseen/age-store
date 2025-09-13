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
VERSION = 0.5
AGE_REPO_URL = "https://github.com/FiloSottile/age"
STORE_DIR = Path("store")
USERS_CONFIG_FILE = Path("users.json")
DEFAULT_USER_SECRET_ENC_FILE = Path("user-secret.age.enc")
MASTER_KEY_FILE = Path("master-key.age.enc")

# Global variable for user secret file path (set by set_user_secret_file)
USER_SECRET_FILE: Path = None  # type: ignore


def enc_suffix_add(file_path: Path) -> Path:
    """Add .enc suffix to a file path.

    Args:
        file_path: Path to add .enc suffix to

    Returns:
        Path with .enc suffix added
    """
    return file_path.with_suffix(file_path.suffix + ".enc")


def enc_suffix_remove(file_path: Path) -> Path:
    """Remove .enc suffix from a file path.

    Args:
        file_path: Path to remove .enc suffix from

    Returns:
        Path with .enc suffix removed
    """
    if file_path.suffix == ".enc":
        return file_path.with_suffix("")
    else:
        return file_path


# Error print alias for stderr output
def eprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def set_user_secret_file(user_secret_path: str | None = None):
    """Set the global USER_SECRET_FILE based on command line arg or default logic.

    Args:
        user_secret_path: Optional path to user secret file from command line
    """
    global USER_SECRET_FILE

    if user_secret_path:
        # Use the provided path
        USER_SECRET_FILE = Path(user_secret_path)
    else:
        default_unenc_file = enc_suffix_remove(DEFAULT_USER_SECRET_ENC_FILE)
        if default_unenc_file.exists():
            # Use unencrypted file if it exists
            USER_SECRET_FILE = default_unenc_file
        else:
            # Default to encrypted file
            USER_SECRET_FILE = DEFAULT_USER_SECRET_ENC_FILE


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
        eprint(f"Error: Invalid JSON in {USERS_CONFIG_FILE}: {e}")
        sys.exit(1)
    except IOError as e:
        eprint(f"Error: Cannot read {USERS_CONFIG_FILE}: {e}")
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
        eprint(
            f"Error: 'age' is not installed. Please visit {AGE_REPO_URL} for installation instructions."
        )
        sys.exit(1)


def age_keygen(args: list[str], input_data: bytes | None = None) -> bytes:
    """Run the `age-keygen` binary with given args via exec_bytes and return stdout bytes."""
    try:
        return exec_bytes(["age-keygen", *args], input_data)
    except FileNotFoundError:
        eprint(
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


def check_file_is_world_accessible(file_path: Path) -> bool:
    """Check if file is accessible by group or others (world accessible).

    Args:
        file_path: Path to check

    Returns True if file is readable by group or others (world accessible).
    Returns False if file is secure (owner-only) or doesn't exist.
    """
    if not file_path.exists():
        return False  # No file means not accessible

    file_stat = file_path.stat()
    return bool(file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH))


def read_user_secret() -> str:
    """Read user secret from the globally set USER_SECRET_FILE.

    - If file ends with .enc, decrypt it using `age` and return the plaintext.
    - Else, enforce secure permissions and return its contents.
    - If file doesn't exist, show error with init hint.
    """
    if not USER_SECRET_FILE.exists():
        eprint(f"Error: User secret file {USER_SECRET_FILE} not found.")
        eprint("Run 'age-store.py init-user' to create a user secret.")
        sys.exit(1)

    if USER_SECRET_FILE.suffix == ".enc" or USER_SECRET_FILE.name.endswith(".age.enc"):
        # Encrypted file - decrypt using age, allowing it to prompt for passphrase via stdin/tty.
        try:
            return age_decrypt_file_with_passphrase(USER_SECRET_FILE)
        except RuntimeError as e:
            eprint(f"Error: Failed to decrypt {USER_SECRET_FILE}: {e}")
            sys.exit(1)
    else:
        # Plain file - warn if using unencrypted secret file
        eprint(
            f"Warning: Using unencrypted user secret at {USER_SECRET_FILE}. Consider using an encrypted secret (.enc suffix)."
        )

        # Check permissions
        if check_file_is_world_accessible(USER_SECRET_FILE):
            eprint(
                f"Error: User secret file {USER_SECRET_FILE} is readable by group or others"
            )
            eprint(f"Fix with: chmod 600 {USER_SECRET_FILE}")
            sys.exit(1)

        # Read and return the private key
        with open(USER_SECRET_FILE, "r") as f:
            return f.read().strip()


def get_master_private_key() -> str:
    """Get the master private key for the current user."""
    if not MASTER_KEY_FILE.exists():
        eprint(
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
        eprint("Error: Access denied")
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
        # Decrypt with old master key
        content = age_decrypt_file_with_identity(secret_file, old_master_private_key)

        # Re-encrypt with new master public key directly to the same file
        age_encrypt_recipients_to_file(content, [new_master_public_key], secret_file)

        print(f"Re-encrypted: {secret_file}")


# Commands


def cmd_bootstrap(initial_user: str):
    """Bootstrap the secret store with initial master keypair."""
    print(f"Bootstrapping secret store for user: {initial_user}")

    ensure_directories()

    # Check if already bootstrapped
    if MASTER_KEY_FILE.exists():
        eprint("Error: Secret store already bootstrapped.")
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


def cmd_add_file(file_path_str: str, force: bool = False):
    """Add a file to the secret store."""
    file_path = Path(file_path_str)

    if not file_path.exists():
        eprint(f"Error: File {file_path} not found")
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
    if secret_file.exists():
        if not force:
            eprint(f"Error: File {secret_file.name} already exists in store")
            eprint("Use --force to overwrite existing files")
            sys.exit(1)

    # Encrypt file with master public key directly to secret_file
    age_encrypt_recipients_to_file(content, [master_public_key], secret_file)

    print(f"File {file_path} added to secret store as {secret_file}")


def cmd_view_file(filename: str):
    """View a file from the secret store."""
    secret_file = STORE_DIR / f"{filename}.enc"

    if not secret_file.exists():
        eprint(f"Error: Secret file {secret_file} not found")
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
        eprint(f"Error: {e}")
        sys.exit(1)


def cmd_bundle_files(filenames: list[str]):
    """Bundle multiple files from the secret store with manifest header."""
    # Get master private key
    master_private_key = get_master_private_key()

    # Collect file data and sizes
    file_data = []
    for filename in filenames:
        secret_file = STORE_DIR / f"{filename}.enc"

        if not secret_file.exists():
            eprint(f"Error: Secret file {secret_file} not found")
            sys.exit(1)

        try:
            content = age_decrypt_file_with_identity(secret_file, master_private_key)
            file_data.append((filename, content))
        except RuntimeError as e:
            eprint(f"Error decrypting {filename}: {e}")
            sys.exit(1)

    # Output file contents with headers
    for i, (filename, content) in enumerate(file_data):
        if i > 0:
            sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.write(f"-- {len(content)} {filename}\n".encode())
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.flush()


def cmd_add_user(username: str, age_pubkey: str):
    """Add a user by adding their age public key to the system."""
    # Check if user already exists in users.json
    users_config = load_users_config()

    if username in users_config:
        eprint(f"Error: User {username} already has access")
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
    # Get old master private key (this verifies the calling user has access)
    old_master_private_key = get_master_private_key()

    # Check if user exists in users.json
    users_config = load_users_config()

    if username not in users_config:
        eprint(f"Error: User {username} does not exist")
        sys.exit(1)

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

    - If `--unencrypted` is provided, save the private key to the specified path or user-secret.age with 600 perms.
    - Otherwise, encrypt the private key with a passphrase and save to the specified path or user-secret.age.enc.
    """
    # Determine output files based on global USER_SECRET_FILE or defaults
    default_unenc_file = enc_suffix_remove(DEFAULT_USER_SECRET_ENC_FILE)
    if (
        USER_SECRET_FILE != default_unenc_file
        and USER_SECRET_FILE != DEFAULT_USER_SECRET_ENC_FILE
    ):
        # Custom path specified via --user-secret
        target_file = USER_SECRET_FILE

        # Validate extension matches the chosen mode
        is_encrypted_extension = (
            target_file.suffix == ".enc" or target_file.name.endswith(".age.enc")
        )
        if unencrypted and is_encrypted_extension:
            eprint(
                f"Error: --unencrypted specified but target file {target_file} has encrypted extension (.enc)"
            )
            eprint("Use a plain file extension or remove --unencrypted flag")
            sys.exit(1)
        elif not unencrypted and not is_encrypted_extension:
            eprint(
                f"Error: encrypted mode selected but target file {target_file} does not have encrypted extension (.enc)"
            )
            eprint("Use an .enc extension or add --unencrypted flag")
            sys.exit(1)
    else:
        # Use default paths
        target_file = (
            default_unenc_file if unencrypted else DEFAULT_USER_SECRET_ENC_FILE
        )

    # For encrypted mode, derive temp file by removing .enc extension
    if not unencrypted:
        temp_file = enc_suffix_remove(target_file)
    else:
        temp_file = None

    # Prevent overwriting existing secrets
    if target_file.exists():
        eprint(f"Error: User secret already exists at {target_file}")
        sys.exit(1)
    if temp_file and temp_file.exists():
        eprint(f"Error: Temporary file {temp_file} already exists")
        sys.exit(1)

    # Generate age keypair for the user
    user_private_key, user_public_key = age_keygen_generate()

    if unencrypted:
        # Save user's private key to target file
        target_file.parent.mkdir(parents=True, exist_ok=True)
        with open(target_file, "w") as f:
            f.write(user_private_key)

        # Set secure permissions (owner read/write only)
        os.chmod(target_file, stat.S_IRUSR | stat.S_IWUSR)

        print("User initialization complete (unencrypted)")
        print(f"Age public key: {user_public_key}")
        print(f"Age private key saved to: {target_file}")
        print("Private key file permissions set to 600 (owner read/write only)")
        return

    # Encrypted user secret
    try:
        # Write plaintext private key to temp file
        temp_file.parent.mkdir(parents=True, exist_ok=True)
        with open(temp_file, "w") as f:
            f.write(user_private_key)
        os.chmod(temp_file, stat.S_IRUSR | stat.S_IWUSR)

        # Run age with passphrase, reading plaintext from temp file
        target_file.parent.mkdir(parents=True, exist_ok=True)
        age_encrypt_file_with_passphrase(temp_file, target_file)

        print("User initialization complete (encrypted)")
        print(f"Age public key: {user_public_key}")
        print(f"Encrypted private key saved to: {target_file}")
        print(
            f"Note: Plaintext private key also present at {temp_file} (permissions 600)."
        )
    except FileNotFoundError as e:
        eprint(f"Error: Required command not found: {e}")
        sys.exit(1)
    except RuntimeError as e:
        eprint(f"Error: {e}")
        sys.exit(1)


def cmd_show_pubkey():
    """Show the user's age public key."""
    # Read user's private key with error handling and permission checks
    user_private_key = read_user_secret()

    # Get user's public key from private key
    try:
        public_key = age_keygen_public_from_private(user_private_key)
        print(public_key)
    except RuntimeError as e:
        eprint(f"Error: Failed to derive public key: {e}")
        sys.exit(1)


def cmd_list_users():
    """List all users with access to secrets."""
    users = get_all_users()
    if users:
        for user in sorted(users):
            print(user)
    else:
        eprint("No users found")


def cmd_list_store():
    """List all available secrets."""
    # Verify user has access before listing files
    get_master_private_key()

    secrets = []
    for secret_file in STORE_DIR.glob("*.enc"):
        secrets.append(secret_file.stem)

    if secrets:
        for secret in sorted(secrets):
            print(secret)
    else:
        eprint("No secrets found")


def launch_shell_with_prompt(
    shell: str, prompt: str = None, args: list[str] = None, env: dict = None
):
    """Launch shell with optionally modified prompt.

    Args:
        shell: Path to shell executable
        prompt: Prompt text to display (without parentheses). If None, no prompt modification.
        args: Additional arguments to pass to shell
        env: Environment variables dict
    """
    shell_basename = os.path.basename(shell)
    shell_args = args or []
    shell_env = env or os.environ.copy()

    if prompt is None:
        # No prompt modification - launch shell directly
        cmd_args = [shell] + shell_args
        try:
            os.execve(shell, cmd_args, shell_env)
        except OSError as e:
            eprint(f"Error: Failed to launch shell {shell}: {e}")
            sys.exit(1)

    # Prompt modification requested
    env_name = f"({prompt})"

    if shell_basename in ["bash", "zsh"]:
        # Use -c to set up environment and exec the shell
        shell_args_str = " ".join(f'"{arg}"' for arg in shell_args)
        cmd_script = f"""
exec {shell} --rcfile <(cat <<'EOF'
# Source the normal rcfile first
[ -f ~/.{shell_basename}rc ] && source ~/.{shell_basename}rc

# Then override PS1
export PS1="{env_name} $PS1"
EOF
) {shell_args_str}
"""
        try:
            os.execve(shell, [shell, "-c", cmd_script], shell_env)
        except OSError as e:
            eprint(f"Error: Failed to launch shell {shell}: {e}")
            sys.exit(1)

    elif shell_basename == "fish":
        # Use --init-command for fish
        init_command = f"""functions --copy fish_prompt fish_prompt_user
function fish_prompt
    fish_prompt_user
    echo -n '{env_name} '
end"""
        cmd_args = [shell, "--init-command", init_command] + shell_args

        try:
            os.execve(shell, cmd_args, shell_env)
        except OSError as e:
            eprint(f"Error: Failed to launch shell {shell}: {e}")
            sys.exit(1)
    else:
        # Unsupported shell, fall back to no prompt modification
        eprint(f"Warning: Shell {shell_basename} prompt modification not supported")
        cmd_args = [shell] + shell_args

        try:
            os.execve(shell, cmd_args, shell_env)
        except OSError as e:
            eprint(f"Error: Failed to launch shell {shell}: {e}")
            sys.exit(1)


def cmd_env_shell(
    env_file_path: str,
    shell: str = None,
    args: list[str] = None,
    hook: str = None,
    no_prompt: bool = False,
    custom_prompt: str = None,
):
    """Launch shell with environment variables loaded from secrets."""
    env_file = Path(env_file_path)

    if not env_file.exists():
        eprint(f"Error: Environment file {env_file} not found")
        sys.exit(1)

    # Get master private key to access secrets
    master_private_key = get_master_private_key()

    # Parse environment file and collect secrets
    env_vars = {}
    try:
        with open(env_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "=" not in line:
                    eprint(f"Error: Invalid format at line {line_num}: {line}")
                    eprint("Expected format: VAR_NAME=secret-name")
                    sys.exit(1)

                var_name, secret_name = line.split("=", 1)
                var_name = var_name.strip()
                secret_name = secret_name.strip()

                if not var_name or not secret_name:
                    eprint(
                        f"Error: Empty variable or secret name at line {line_num}: {line}"
                    )
                    sys.exit(1)

                # Load secret content
                secret_file = STORE_DIR / f"{secret_name}.enc"
                if not secret_file.exists():
                    eprint(
                        f"Error: Secret file {secret_file} not found for variable {var_name}"
                    )
                    sys.exit(1)

                try:
                    content = age_decrypt_file_with_identity(
                        secret_file, master_private_key
                    )
                    env_vars[var_name] = content.decode().strip()
                except RuntimeError as e:
                    eprint(
                        f"Error: Failed to decrypt {secret_name} for {var_name}: {e}"
                    )
                    sys.exit(1)

    except IOError as e:
        eprint(f"Error: Cannot read environment file {env_file}: {e}")
        sys.exit(1)

    # Execute hook if provided
    if hook:
        try:
            # Execute hook with current environment + loaded secrets
            hook_env = os.environ.copy()
            hook_env.update(env_vars)

            result = subprocess.run(
                [hook], stdout=subprocess.PIPE, text=True, env=hook_env
            )

            if result.returncode != 0:
                eprint(f"Error: Hook script exited with code {result.returncode}")
                sys.exit(1)

            # Parse hook output for additional environment variables
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue

                if "=" not in line:
                    eprint(f"Warning: Hook output line ignored (no '='): {line}")
                    continue

                var_name, var_value = line.split("=", 1)
                var_name = var_name.strip()
                var_value = var_value.strip()

                if not var_name:
                    eprint(
                        f"Warning: Hook output line ignored (empty variable name): {line}"
                    )
                    continue

                env_vars[var_name] = var_value

        except FileNotFoundError:
            eprint(f"Error: Hook script not found: {hook}")
            sys.exit(1)
        except OSError as e:
            eprint(f"Error: Failed to execute hook script: {e}")
            sys.exit(1)

    # Determine shell to use
    user_shell = shell or os.environ.get("SHELL", "/bin/sh")

    # Prepare environment with loaded secrets
    new_env = os.environ.copy()
    new_env.update(env_vars)

    # Add AGE_STORE_ENV variable pointing to the env file
    new_env["AGE_STORE_ENV"] = env_file_path

    # Determine prompt to use (CLI custom prompt has highest precedence)
    prompt_text = None
    if not no_prompt:
        if custom_prompt:
            # CLI custom prompt (highest precedence)
            prompt_text = custom_prompt
        elif "AGE_STORE_PROMPT" in env_vars:
            # Hook output prompt
            prompt_text = env_vars["AGE_STORE_PROMPT"]
        else:
            # Default prompt
            prompt_text = f"age-store:{env_file.stem}"

    print(
        f"Launching {user_shell} with {len(env_vars)} environment variables from secrets..."
    )
    if args:
        print(f"Shell arguments: {' '.join(args)}")

    # Launch shell with optional prompt modification
    launch_shell_with_prompt(user_shell, prompt_text, args, new_env)


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
    default_unenc_file = enc_suffix_remove(DEFAULT_USER_SECRET_ENC_FILE)
    if default_unenc_file.exists():
        results.append(
            ("WARN", f"Unencrypted user secret present at {default_unenc_file}")
        )
        if check_file_is_world_accessible(default_unenc_file):
            results.append(
                (
                    "ERROR",
                    f"Permissions for {default_unenc_file} are too open; run: chmod 600 {default_unenc_file}",
                )
            )
        else:
            results.append(
                (
                    "OK",
                    f"Permissions for {default_unenc_file} are 600 (owner-only)",
                )
            )
    elif DEFAULT_USER_SECRET_ENC_FILE.exists():
        results.append(
            ("OK", f"User secret is encrypted ({DEFAULT_USER_SECRET_ENC_FILE})")
        )
    else:
        results.append(("WARN", "No user secret found (run 'init-user')"))

    # Attempt to load current user's private key (may prompt if encrypted)
    user_private_key: str | None = None
    try:
        if default_unenc_file.exists():
            with open(default_unenc_file, "r") as f:
                user_private_key = f.read().strip()
        elif DEFAULT_USER_SECRET_ENC_FILE.exists():
            user_private_key = age_decrypt_file_with_passphrase(
                DEFAULT_USER_SECRET_ENC_FILE
            )
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
    """Encrypt plaintext user secret to encrypted version and delete plaintext."""
    # Determine source file from --user-secret argument or default
    default_unenc_file = enc_suffix_remove(DEFAULT_USER_SECRET_ENC_FILE)
    if (
        USER_SECRET_FILE != default_unenc_file
        and USER_SECRET_FILE != DEFAULT_USER_SECRET_ENC_FILE
    ):
        # Custom path specified via --user-secret (treated as source)
        source_file = USER_SECRET_FILE

        if source_file.suffix == ".enc" or source_file.name.endswith(".age.enc"):
            eprint(f"Error: Source file {source_file} is already encrypted")
            sys.exit(1)

        # Derive encrypted target by adding .enc extension
        target_file = enc_suffix_add(source_file)
    else:
        # Use default files
        source_file = default_unenc_file
        target_file = DEFAULT_USER_SECRET_ENC_FILE

    # Preconditions
    if not source_file.exists():
        eprint(f"Error: Plaintext secret {source_file} not found.")
        sys.exit(1)

    if target_file.exists():
        eprint(f"Error: Encrypted file {target_file} already exists")
        sys.exit(1)

    # Run age -p to produce encrypted file
    try:
        target_file.parent.mkdir(parents=True, exist_ok=True)
        age_encrypt_file_with_passphrase(source_file, target_file)
    except RuntimeError as e:
        eprint(f"Error: Failed to encrypt user secret: {e}")
        sys.exit(1)

    # Verify encrypted file now exists, then remove plaintext
    if not target_file.exists():
        eprint(f"Error: Failed to create {target_file}")
        sys.exit(1)

    try:
        source_file.unlink()
    except OSError as e:
        eprint(f"Error: Encrypted file created but failed to delete plaintext: {e}")
        sys.exit(1)

    print(f"Migrated user secret to {target_file} and removed {source_file}")


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

    # Global arguments
    parser.add_argument(
        "--user-secret",
        help="Path to user secret file (encrypted .enc or plain file)",
        metavar="PATH",
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

    # Bundle files command
    bundle_files_parser = subparsers.add_parser(
        "bundle", help="Bundle multiple files from the secret store with manifest"
    )
    bundle_files_parser.add_argument(
        "files", nargs="+", help="Names of files to bundle (without .enc extension)"
    )

    # Env shell command
    env_shell_parser = subparsers.add_parser(
        "env-shell", help="Launch shell with environment variables from secrets"
    )
    env_shell_parser.add_argument(
        "env_file",
        help="Environment file with VAR_NAME=secret-name pairs (one per line, # for comments)",
    )
    env_shell_parser.add_argument(
        "--shell", help="Custom shell to launch (default: $SHELL or /bin/sh)"
    )
    env_shell_parser.add_argument(
        "args", nargs="*", help="Arguments to pass to the shell (use -- to separate)"
    )
    env_shell_parser.add_argument(
        "--hook",
        help="Executable that outputs additional FOO=BAR environment variables to stdout",
    )
    env_shell_parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Don't modify shell prompt to show environment name",
    )
    env_shell_parser.add_argument(
        "--custom-prompt",
        help="Custom prompt prefix to use instead of default 'age-store:<env-file>'",
    )

    # Add file command
    add_file_parser = subparsers.add_parser(
        "add", help="Add a file to the secret store"
    )
    add_file_parser.add_argument("file", help="Path to the file to add")
    add_file_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing files"
    )

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

    # Set the global user secret file path
    set_user_secret_file(args.user_secret)

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
            cmd_add_file(args.file, args.force)
        elif args.command == "view":
            cmd_view_file(args.file)
        elif args.command == "bundle":
            cmd_bundle_files(args.files)
        elif args.command == "env-shell":
            cmd_env_shell(
                args.env_file,
                args.shell,
                args.args,
                args.hook,
                args.no_prompt,
                args.custom_prompt,
            )
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
        eprint("\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        eprint(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
