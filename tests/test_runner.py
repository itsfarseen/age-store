#!/usr/bin/env python3
"""
Age Store CLI Test Runner
"""

import argparse
import os
import random
import shutil
import string
import subprocess
import sys
from pathlib import Path


class T:
    """Terminal color helper with ANSI escape sequences."""

    red, green, blue, yellow, grey, bold, clear = (
        "\033[31m",
        "\033[32m",
        "\033[34m",
        "\033[33m",
        "\033[90m",
        "\033[1m",
        "\033[0m",
    )


# Test configuration
TESTS_DIR = Path(__file__).parent
TMP_DATA_DIR = Path("tmp-data")
AGE_STORE_SCRIPT = Path("../age-store.py")
USER_SECRETS_DIR = Path("user-secrets")
USER1_SECRET = Path("user-secrets/user1.age")
USER2_SECRET = Path("user-secrets/user2.age")
STORE_SUBDIR = Path("store")
USERS_JSON = Path("users.json")
MASTER_KEY_FILE = Path("master-key.age.enc")

# Global verbose flag
verbose = False


def cleanup_and_setup():
    """Clean up tmp-data folder and create test directories."""
    # Work from tests directory for setup
    if TMP_DATA_DIR.exists():
        shutil.rmtree(TMP_DATA_DIR)

    TMP_DATA_DIR.mkdir(exist_ok=True)
    (TMP_DATA_DIR / "user-secrets").mkdir(exist_ok=True)


def run_age_store_command(
    command,
    capture_output=True,
    input_text=None,
    description=None,
    user_secret_path=None,
):
    """Run age-store.py command with working directory in tmp-data folder."""
    cmd = [str(AGE_STORE_SCRIPT)]

    # Add --user-secret argument if provided
    if user_secret_path:
        cmd.extend(["--user-secret", str(user_secret_path)])

    cmd.extend(command)

    # Print description if verbose mode is enabled
    if verbose and description:
        print(f"\n◼ {description}")

    # Print the command being executed
    user_secret_part = f"--user-secret {user_secret_path} " if user_secret_path else ""
    args_str = f"{user_secret_part}{' '.join(command)}"
    print(
        f"{T.yellow}age-store.py {args_str}{T.clear}",
        end="\r",
    )

    if capture_output:
        result = subprocess.run(cmd, capture_output=True, text=True, input=input_text)

        # Rewrite the line with success/failure color
        if result.returncode == 0:
            command_color = T.green
        else:
            command_color = T.red

        print(f"{command_color}age-store.py {args_str}{T.clear}")

        # Print stderr first if it exists (with yellow border)
        if result.stderr.strip():
            print_with_left_border(
                result.stderr.rstrip(), border_color=T.yellow, text_color=T.grey
            )

        # Print output if verbose mode is enabled
        if verbose and result.stdout.strip():
            print_with_left_border(
                result.stdout.rstrip(), border_color=T.grey, text_color=T.grey
            )

        return result.returncode, result.stdout, result.stderr
    else:
        result = subprocess.run(cmd, input=input_text, text=True, cwd=".")
        return result.returncode, "", ""


def verbose_check(description, condition):
    """Print check description and result if verbose mode is enabled, return condition value."""
    if verbose:
        if condition:
            print(f"{T.green}▸ check {description} [OK]{T.clear}")
        else:
            print(f"{T.red}▸ check {description} [FAIL]{T.clear}")
    return condition


def create_test_file(filename, content):
    """Create a test file in the current directory (tmp-data)."""
    test_file_path = Path(filename)
    with open(test_file_path, "w") as f:
        f.write(content)
    return test_file_path


def extract_public_key(output):
    """Extract age public key from command output."""
    # Remove only one trailing newline, preserve exact format
    cleaned = output.rstrip("\n")
    return cleaned if cleaned.startswith("age1") else None


def generate_random_content():
    """Generate random filename and content for testing."""
    # Generate random filename
    filename = "".join(random.choices(string.ascii_lowercase, k=8)) + "-test.txt"
    # Generate random content
    content = "".join(random.choices(string.ascii_letters + string.digits + " ", k=20))
    return filename, content


def test_user_has_access(user_name, user_secret_path):
    """
    Test that a user has full access to the store.
    Returns (success, error_message) tuple.
    """
    # Generate random test data
    test_filename, test_content = generate_random_content()

    # Create test file
    test_file = create_test_file(test_filename, test_content)

    try:
        # Test 1: Add file to store
        returncode, stdout, stderr = run_age_store_command(
            ["add", test_file.name],
            description=f"add {test_filename} using {user_name} credentials",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(f"{user_name} can add files", returncode == 0):
            return False, f"{user_name} cannot add files: {stderr}"

        # Check encrypted file exists
        encrypted_file = STORE_SUBDIR / f"{test_filename}.enc"
        if not verbose_check(
            f"{user_name} encrypted file was created", encrypted_file.exists()
        ):
            return False, f"{user_name} encrypted file not created"

        # Test 2: List files and verify new file appears
        returncode, stdout, stderr = run_age_store_command(
            ["ls"],
            description=f"list files using {user_name} credentials",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(f"{user_name} can list files", returncode == 0):
            return False, f"{user_name} cannot list files: {stderr}"

        if not verbose_check(
            f"{user_name} sees added file in listing", test_filename in stdout
        ):
            return False, f"{user_name} added file not found in listing: {stdout}"

        # Test 3: View the file content
        returncode, stdout, stderr = run_age_store_command(
            ["view", test_filename],
            description=f"view {test_filename} using {user_name} credentials",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(f"{user_name} can view files", returncode == 0):
            return False, f"{user_name} cannot view files: {stderr}"

        if not verbose_check(
            f"{user_name} file content matches", stdout == test_content
        ):
            return (
                False,
                f"{user_name} file content mismatch. Expected: '{test_content}', Got: '{stdout}'",
            )

        # Test 4: Test --force functionality using the same file
        # Try to add the same file again without --force (should fail)
        returncode, stdout, stderr = run_age_store_command(
            ["add", test_file.name],
            description=f"try to add {test_filename} again without --force (should fail)",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(
            f"{user_name} add without --force fails for existing file", returncode != 0
        ):
            return False, f"{user_name} can overwrite existing file without --force"

        if not verbose_check(
            f"{user_name} add without --force suggests using --force",
            "Use --force to overwrite existing files" in stderr,
        ):
            return False, f"{user_name} error message doesn't suggest --force: {stderr}"

        # Modify the file content before re-adding with --force
        modified_content = test_content + " MODIFIED"
        with open(test_file, "w") as f:
            f.write(modified_content)

        # Now add same file again with --force (should succeed)
        returncode, stdout, stderr = run_age_store_command(
            ["add", "--force", test_file.name],
            description=f"add {test_filename} again with --force (should succeed)",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(
            f"{user_name} add with --force succeeds for existing file", returncode == 0
        ):
            return (
                False,
                f"{user_name} cannot overwrite existing file with --force: {stderr}",
            )

        # Verify the file content was actually overwritten by viewing it
        returncode, view_stdout, stderr = run_age_store_command(
            ["view", test_filename],
            description=f"verify {test_filename} content was overwritten",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(f"{user_name} can view overwritten file", returncode == 0):
            return False, f"{user_name} cannot view overwritten file: {stderr}"

        if not verbose_check(
            f"{user_name} overwritten file content matches modified content",
            view_stdout == modified_content,
        ):
            return (
                False,
                f"{user_name} file was not properly overwritten. Expected: '{modified_content}', Got: '{view_stdout}'",
            )

        # Test 5: List users and verify user is included
        returncode, stdout, stderr = run_age_store_command(
            ["admin", "list-users"],
            description=f"list users using {user_name} credentials",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(f"{user_name} can list users", returncode == 0):
            return False, f"{user_name} cannot list users: {stderr}"

        if not verbose_check(f"{user_name} appears in user list", user_name in stdout):
            return False, f"{user_name} not found in user list: {stdout}"

        return True, None

    finally:
        # Clean up test file
        if test_file.exists():
            test_file.unlink()


def test_user_has_no_access(
    user_name, user_secret_path, valid_user_name, valid_user_secret_path
):
    """
    Test that a user has no access to the store (all operations should fail).
    Uses a valid user to verify that operations didn't actually succeed.
    Creates a test file with valid user credentials for view testing.
    Returns (success, error_message) tuple.
    """
    # Generate random test data
    test_filename, test_content = generate_random_content()

    # Create test file
    test_file = create_test_file(test_filename, test_content)

    try:
        # Test 1: Add file should fail (without --force)
        returncode, stdout, stderr = run_age_store_command(
            ["add", test_file.name],
            description=f"try to add {test_filename} using {user_name} credentials (should fail)",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(f"{user_name} add operation fails", returncode != 0):
            return False, f"{user_name} can still add files after removal"

        if not verbose_check(
            f"{user_name} add operation shows access denied", "Access denied" in stderr
        ):
            return (
                False,
                f"{user_name} add operation failed but without 'Access denied' error: {stderr}",
            )

        # Test 1b: Add file should also fail with --force
        returncode, stdout, stderr = run_age_store_command(
            ["add", "--force", test_file.name],
            description=f"try to add {test_filename} with --force using {user_name} credentials (should still fail)",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(
            f"{user_name} add operation with --force fails", returncode != 0
        ):
            return False, f"{user_name} can still add files with --force after removal"

        if not verbose_check(
            f"{user_name} add operation with --force shows access denied",
            "Access denied" in stderr,
        ):
            return (
                False,
                f"{user_name} add operation with --force failed but without 'Access denied' error: {stderr}",
            )

        # Verify with valid user that file was not actually added
        returncode, valid_stdout, stderr = run_age_store_command(
            ["ls"],
            description=f"verify {test_filename} not added using {valid_user_name} credentials",
            user_secret_path=valid_user_secret_path,
        )
        if not verbose_check(f"valid user can list files", returncode == 0):
            return False, f"{valid_user_name} cannot list files: {stderr}"

        if not verbose_check(
            f"unauthorized file not in store", test_filename not in valid_stdout
        ):
            return (
                False,
                f"File {test_filename} was incorrectly added to store: {valid_stdout}",
            )

        # Test 2: List files should fail with access denied
        returncode, stdout, stderr = run_age_store_command(
            ["ls"],
            description=f"list files using {user_name} credentials (should fail)",
            user_secret_path=user_secret_path,
        )
        if not verbose_check(f"{user_name} list operation fails", returncode != 0):
            return False, f"{user_name} can still list files after removal"

        if not verbose_check(
            f"{user_name} list operation shows access denied", "Access denied" in stderr
        ):
            return (
                False,
                f"{user_name} list operation failed but without 'Access denied' error: {stderr}",
            )

        # Test 3: View files should fail
        # Create a test file with valid user credentials for view testing
        view_test_filename, view_test_content = generate_random_content()
        view_test_file = create_test_file(view_test_filename, view_test_content)

        try:
            # Add test file using valid user credentials
            returncode, stdout, stderr = run_age_store_command(
                ["add", view_test_file.name],
                description=f"add {view_test_filename} for view test using {valid_user_name} credentials",
                user_secret_path=valid_user_secret_path,
            )
            if not verbose_check("view test file added", returncode == 0):
                return False, f"Failed to add view test file: {stderr}"

            # Test view operation with the newly created file
            returncode, stdout, stderr = run_age_store_command(
                ["view", view_test_filename],
                description=f"try to view {view_test_filename} using {user_name} credentials (should fail)",
                user_secret_path=user_secret_path,
            )
            if not verbose_check(f"{user_name} view operation fails", returncode != 0):
                return False, f"{user_name} can still view files after removal"

            if not verbose_check(
                f"{user_name} view operation shows access denied",
                "Access denied" in stderr,
            ):
                return (
                    False,
                    f"{user_name} view operation failed but without 'Access denied' error: {stderr}",
                )

            # Test 3b: Try to overwrite the existing view test file with --force (should also fail)
            # Modify the view test file content locally
            modified_overwrite_content = view_test_content + " MODIFIED"
            with open(view_test_file, "w") as f:
                f.write(modified_overwrite_content)

            # Try to overwrite existing file with --force using unauthorized user (should fail)
            returncode, stdout, stderr = run_age_store_command(
                ["add", "--force", view_test_file.name],
                description=f"try to overwrite {view_test_filename} with --force using {user_name} credentials (should fail)",
                user_secret_path=user_secret_path,
            )
            if not verbose_check(
                f"{user_name} overwrite with --force fails", returncode != 0
            ):
                return (
                    False,
                    f"{user_name} can overwrite existing files with --force after removal",
                )

            if not verbose_check(
                f"{user_name} overwrite with --force shows access denied",
                "Access denied" in stderr,
            ):
                return (
                    False,
                    f"{user_name} overwrite with --force failed but without 'Access denied' error: {stderr}",
                )

            # Verify with valid user that file content in store was not changed
            returncode, store_view_stdout, stderr = run_age_store_command(
                ["view", view_test_filename],
                description=f"verify {view_test_filename} content in store unchanged using {valid_user_name} credentials",
                user_secret_path=valid_user_secret_path,
            )
            if not verbose_check(
                "valid user can view file after failed overwrite", returncode == 0
            ):
                return (
                    False,
                    f"{valid_user_name} cannot view file after failed overwrite: {stderr}",
                )

            if not verbose_check(
                "file content in store unchanged after failed overwrite",
                store_view_stdout == view_test_content,
            ):
                return (
                    False,
                    f"File {view_test_filename} in store was incorrectly modified. Expected: '{view_test_content}', Got: '{store_view_stdout}'",
                )

        finally:
            # Clean up view test file
            if view_test_file.exists():
                view_test_file.unlink()

        # Test 4: Admin operations should fail with access denied
        admin_operations = [
            (["admin", "add-user", "dummy", "age1abcdef"], "add user"),
            (["admin", "rotate-master-key"], "rotate master key"),
        ]

        for admin_command, operation_name in admin_operations:
            returncode, stdout, stderr = run_age_store_command(
                admin_command,
                description=f"try to {operation_name} using {user_name} credentials (should fail)",
                user_secret_path=user_secret_path,
            )
            if not verbose_check(
                f"{user_name} {operation_name} operation fails", returncode != 0
            ):
                return (
                    False,
                    f"{user_name} can still perform {operation_name} after removal",
                )

            if not verbose_check(
                f"{user_name} {operation_name} operation shows access denied",
                "Access denied" in stderr,
            ):
                return (
                    False,
                    f"{user_name} {operation_name} operation failed but without 'Access denied' error: {stderr}",
                )

        # Verify with valid user that dummy user was not actually added
        returncode, users_stdout, stderr = run_age_store_command(
            ["admin", "list-users"],
            description=f"verify dummy user not added using {valid_user_name} credentials",
            user_secret_path=valid_user_secret_path,
        )
        if not verbose_check(f"valid user can list users", returncode == 0):
            return False, f"{valid_user_name} cannot list users: {stderr}"

        if not verbose_check(
            f"dummy user not in user list", "dummy" not in users_stdout
        ):
            return False, f"User 'dummy' was incorrectly added to users: {users_stdout}"

        return True, None

    finally:
        # Clean up test file
        if test_file.exists():
            test_file.unlink()


def test_init_and_bootstrap():
    """Test basic init-user and admin bootstrap functionality."""
    # Test init-user - create user1 secret
    returncode, stdout, stderr = run_age_store_command(
        ["init-user", "--unencrypted"],
        description="initialize user1 with unencrypted private key",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"init-user failed: {stderr}"

    if not verbose_check(
        "output contains completion message",
        "User initialization complete (unencrypted)" in stdout,
    ):
        return False, f"init-user output unexpected: {stdout}"

    # Check that user1 secret file was created
    if not verbose_check("user1 secret file was created", USER1_SECRET.exists()):
        return False, "user1 secret not created"

    # Test init-user - create user2 secret
    returncode, stdout, stderr = run_age_store_command(
        ["init-user", "--unencrypted"],
        description="initialize user2 with unencrypted private key",
        user_secret_path=USER2_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"init-user user2 failed: {stderr}"

    if not verbose_check(
        "output contains completion message",
        "User initialization complete (unencrypted)" in stdout,
    ):
        return False, f"init-user user2 output unexpected: {stdout}"

    # Check that user2 secret file was created
    if not verbose_check("user2 secret file was created", USER2_SECRET.exists()):
        return False, "user2 secret not created"

    # Get public keys and verify they are different
    returncode, user1_pubkey_stdout, stderr = run_age_store_command(
        ["show-pubkey"],
        description="get user1's public key",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"show-pubkey user1 failed: {stderr}"

    user1_pubkey = extract_public_key(user1_pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", user1_pubkey is not None
    ):
        return (
            False,
            f"No valid public key found in user1 output: {user1_pubkey_stdout}",
        )

    returncode, user2_pubkey_stdout, stderr = run_age_store_command(
        ["show-pubkey"],
        description="get user2's public key",
        user_secret_path=USER2_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"show-pubkey user2 failed: {stderr}"

    user2_pubkey = extract_public_key(user2_pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", user2_pubkey is not None
    ):
        return (
            False,
            f"No valid public key found in user2 output: {user2_pubkey_stdout}",
        )

    # Verify user1 and user2 have different public keys
    if not verbose_check(
        "user1 and user2 have different public keys", user1_pubkey != user2_pubkey
    ):
        return False, f"user1 and user2 have identical public keys: {user1_pubkey}"

    # Use user1 public key for bootstrap
    pubkey = user1_pubkey

    # Test bootstrap
    returncode, stdout, stderr = run_age_store_command(
        ["admin", "bootstrap", "user1"],
        description="bootstrap the store with user1",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"bootstrap failed: {stderr}"

    # Check that store directory and files were created
    if not verbose_check("store directory was created", STORE_SUBDIR.exists()):
        return False, "store directory not created"

    if not verbose_check("users.json was created", USERS_JSON.exists()):
        return False, "users.json not created"

    if not verbose_check("master-key.age.enc was created", MASTER_KEY_FILE.exists()):
        return False, "master-key.age.enc not created"

    return True, None


def test_user1_access():
    """Test user1 can add, view, and list files."""
    return test_user_has_access("user1", USER1_SECRET)


def test_add_and_list_users():
    """Test adding user2 to the store and listing users."""
    # Get user2's public key
    returncode, pubkey_stdout, stderr = run_age_store_command(
        ["show-pubkey"],
        description="get user2's public key",
        user_secret_path=USER2_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get user2 pubkey: {stderr}"

    user2_pubkey = extract_public_key(pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", user2_pubkey is not None
    ):
        return False, f"No valid public key found in user2 output: {pubkey_stdout}"

    # Add user2 to the store (using user1's credentials)
    returncode, stdout, stderr = run_age_store_command(
        ["admin", "add-user", "user2", user2_pubkey],
        description="add user2 to the store's user list",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"add-user failed: {stderr}"

    # Test listing users with user1 credentials
    returncode, stdout, stderr = run_age_store_command(
        ["admin", "list-users"],
        description="list all users using user1 credentials",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("user1 can list users", returncode == 0):
        return False, f"user1 list-users failed: {stderr}"

    # Should contain both users
    if not verbose_check("output contains user1", "user1" in stdout):
        return False, f"user1 not found in list-users output: {stdout}"

    if not verbose_check("output contains user2", "user2" in stdout):
        return False, f"user2 not found in list-users output: {stdout}"

    # Should show exactly 2 users
    lines = stdout.split("\n")
    # Count lines that contain user entries
    user_count = sum(
        1 for line in lines if line and ("user1" in line or "user2" in line)
    )

    if not verbose_check("exactly 2 users found", user_count == 2):
        return False, f"Expected exactly 2 users, found {user_count}: {stdout}"

    # Test that user2 can also list users
    returncode, stdout, stderr = run_age_store_command(
        ["admin", "list-users"],
        description="list all users using user2 credentials",
        user_secret_path=USER2_SECRET,
    )
    if not verbose_check("user2 can list users", returncode == 0):
        return False, f"user2 list-users failed: {stderr}"

    # Should contain both users when user2 lists them
    if not verbose_check("user2 sees user1 in listing", "user1" in stdout):
        return False, f"user1 not found in user2's list-users output: {stdout}"

    if not verbose_check("user2 sees user2 in listing", "user2" in stdout):
        return False, f"user2 not found in user2's list-users output: {stdout}"

    return True, None


def test_user2_access():
    """Test that user2 can access files after being added to the store."""
    return test_user_has_access("user2", USER2_SECRET)


def test_master_key_rotation():
    """Test master key rotation and file re-encryption."""
    # Add two random files before rotation
    test_file1_name, test_file1_content = generate_random_content()
    test_file2_name, test_file2_content = generate_random_content()

    test_file1 = create_test_file(test_file1_name, test_file1_content)
    test_file2 = create_test_file(test_file2_name, test_file2_content)

    # Add first file using user1
    returncode, stdout, stderr = run_age_store_command(
        ["add", test_file1.name],
        description=f"add {test_file1_name} before rotation",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("file1 added successfully", returncode == 0):
        return False, f"Failed to add file1 before rotation: {stderr}"

    # Add second file using user2
    returncode, stdout, stderr = run_age_store_command(
        ["add", test_file2.name],
        description=f"add {test_file2_name} before rotation",
        user_secret_path=USER2_SECRET,
    )
    if not verbose_check("file2 added successfully", returncode == 0):
        return False, f"Failed to add file2 before rotation: {stderr}"

    # Clean up original test files
    test_file1.unlink()
    test_file2.unlink()

    # Get file listing before rotation
    returncode, listing_before, stderr = run_age_store_command(
        ["ls"],
        description="get file listing before rotation",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("listing before rotation succeeded", returncode == 0):
        return False, f"Failed to get listing before rotation: {stderr}"

    # Get original encrypted file contents
    encrypted_files = {}
    for filename in [test_file1_name, test_file2_name]:
        encrypted_file = STORE_SUBDIR / f"{filename}.enc"
        if encrypted_file.exists():
            with open(encrypted_file, "rb") as f:
                encrypted_files[filename] = f.read()

    # Rotate master key (using user1 credentials)
    returncode, stdout, stderr = run_age_store_command(
        ["admin", "rotate-master-key"],
        description="rotate the master key and re-encrypt all files",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("key rotation succeeded", returncode == 0):
        return False, f"rotate-master-key failed: {stderr}"

    # Verify encrypted file contents changed
    for filename, original_content in encrypted_files.items():
        encrypted_file = STORE_SUBDIR / f"{filename}.enc"
        with open(encrypted_file, "rb") as f:
            new_content = f.read()

        if original_content == new_content:
            return (
                False,
                f"Encrypted file {filename} content didn't change after key rotation",
            )

    # Get file listing after rotation
    returncode, listing_after, stderr = run_age_store_command(
        ["ls"],
        description="get file listing after rotation",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("listing after rotation succeeded", returncode == 0):
        return False, f"Failed to get listing after rotation: {stderr}"

    # Verify file listing is the same before and after rotation
    if not verbose_check(
        "file listing unchanged after rotation",
        set(listing_before.split("\n")) == set(listing_after.split("\n")),
    ):
        return (
            False,
            f"File listing changed after rotation.\nBefore: {listing_before}\nAfter: {listing_after}",
        )

    # Test that both user1 and user2 can still access both files after rotation
    test_cases = [
        (test_file1_name, test_file1_content),
        (test_file2_name, test_file2_content),
    ]

    for filename, expected_content in test_cases:
        for user_name, user_secret in [
            ("user1", USER1_SECRET),
            ("user2", USER2_SECRET),
        ]:
            returncode, stdout, stderr = run_age_store_command(
                ["view", filename],
                description=f"verify {user_name} can access {filename} after rotation",
                user_secret_path=user_secret,
            )
            if not verbose_check(f"{user_name} can access {filename}", returncode == 0):
                return (
                    False,
                    f"{user_name} cannot access {filename} after rotation: {stderr}",
                )

            if not verbose_check(
                f"{user_name} {filename} content matches",
                stdout == expected_content,
            ):
                return (
                    False,
                    f"{user_name} {filename} content mismatch after rotation. Expected: '{expected_content}', Got: '{stdout}'",
                )

    return True, None


def test_user_removal():
    """Test removing user access and verifying access is lost."""
    # Store original user2 pubkey
    returncode, original_pubkey_stdout, stderr = run_age_store_command(
        ["show-pubkey"],
        description="get user2 public key before removal",
        user_secret_path=USER2_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get user2 pubkey: {stderr}"

    original_pubkey = extract_public_key(original_pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", original_pubkey is not None
    ):
        return False, f"No valid original pubkey found: {original_pubkey_stdout}"

    # Remove user2 from store (using user1 credentials)
    returncode, stdout, stderr = run_age_store_command(
        ["admin", "remove-user", "user2"],
        description="remove user2 from store",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"remove-user failed: {stderr}"

    # Verify user2 pubkey hasn't changed
    returncode, current_pubkey_stdout, stderr = run_age_store_command(
        ["show-pubkey"],
        description="verify user2 public key after removal",
        user_secret_path=USER2_SECRET,
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get user2 pubkey after removal: {stderr}"

    current_pubkey = extract_public_key(current_pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", current_pubkey is not None
    ):
        return (
            False,
            f"No valid current pubkey found after removal: {current_pubkey_stdout}",
        )

    if not verbose_check(
        "public key unchanged after removal", original_pubkey == current_pubkey
    ):
        return (
            False,
            f"User2 pubkey changed after removal: {original_pubkey} -> {current_pubkey}",
        )

    # Test that user2 has lost access using the no access test function
    success, error_message = test_user_has_no_access(
        "user2", USER2_SECRET, "user1", USER1_SECRET
    )
    if not success:
        return False, error_message

    # Test remove-user operation (try to remove user1 which should fail since user2 has no access)
    admin_operations = [
        (["admin", "remove-user", "user1"], "remove user"),
    ]

    for admin_command, operation_name in admin_operations:
        returncode, stdout, stderr = run_age_store_command(
            admin_command,
            description=f"try to {operation_name} using user2 credentials (should fail)",
            user_secret_path=USER2_SECRET,
        )
        if not verbose_check(
            f"user2 {operation_name} operation fails", returncode != 0
        ):
            return False, f"user2 can still perform {operation_name} after removal"

        if not verbose_check(
            f"user2 {operation_name} operation shows access denied",
            "Access denied" in stderr,
        ):
            return (
                False,
                f"user2 {operation_name} operation failed but without 'Access denied' error: {stderr}",
            )

    # Verify with valid user that user1 still exists in the user list (wasn't removed)
    returncode, users_stdout, stderr = run_age_store_command(
        ["admin", "list-users"],
        description=f"verify user1 still exists using user1 credentials",
        user_secret_path=USER1_SECRET,
    )
    if not verbose_check("valid user can list users", returncode == 0):
        return False, f"user1 cannot list users: {stderr}"

    if not verbose_check(
        "user1 still exists after failed remove", "user1" in users_stdout
    ):
        return False, f"User1 was incorrectly removed from users: {users_stdout}"

    return True, None


def get_terminal_width():
    """Get the terminal width, with fallback."""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80  # fallback width if terminal size can't be determined


def print_horizontal_rule():
    """Print a horizontal rule spanning the terminal width."""
    width = get_terminal_width()
    print(f"{T.grey}{'─' * width}{T.clear}")


def print_with_left_border(text, border_char="│", border_color=None, text_color=None):
    """Print text with a left border, wrapping lines to terminal width."""
    width = get_terminal_width()
    border_prefix = f"{border_color or ''}{border_char}{T.clear} {text_color or ''}"
    content_width = width - len(border_char) - 1  # Account for border and space

    lines = text.split("\n")
    for line in lines:
        if not line.strip():  # Handle empty lines
            print(f"{border_prefix}{T.clear}")
        elif len(line) <= content_width:
            print(f"{border_prefix}{line}{T.clear}")
        else:
            # Wrap long lines
            while line:
                chunk = line[:content_width]
                line = line[content_width:]
                print(f"{border_prefix}{chunk}{T.clear}")


def run_test(test_name, test_func, test_number, total_tests):
    """Run a single test and report results."""
    print_horizontal_rule()
    print(
        f"{T.bold}{T.yellow}[{test_number}/{total_tests}] Running {test_name}...{T.clear}"
    )
    try:
        success, message = test_func()
        if success:
            print(f"{T.bold}{T.green}PASS{T.clear}")
            return True
        else:
            print(f"{T.bold}{T.red}FAIL{T.clear}")
            if message:
                print(f"  Error: {message}")
            return False
    except Exception as e:
        print(f"{T.bold}{T.red}FAIL{T.clear}")
        print(f"  Exception: {e}")
        return False


def main():
    """Main test runner."""
    global verbose

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Age Store CLI Test Runner")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print the output of each age store command",
    )
    args = parser.parse_args()

    # Set global verbose flag
    verbose = args.verbose

    # Simple header
    width = get_terminal_width()
    print(f"{T.bold}{T.yellow}Age Store CLI Test Runner{T.clear}")
    print(f"{T.blue}{'─' * width}{T.clear}")

    # Setup
    print("Setting up test environment...")
    cleanup_and_setup()

    # Change to tmp-data directory for consistent working directory
    os.chdir(TMP_DATA_DIR)

    # Track test results
    passed = 0
    total = 0

    # Calculate total tests
    total_test_count = 6  # Update this if you add/remove tests

    # Basic init and bootstrap tests
    total += 1
    result = run_test(
        "test_init_and_bootstrap", test_init_and_bootstrap, total, total_test_count
    )
    if result is True:
        passed += 1
    elif result is None:
        total -= 1  # Don't count skipped tests

    # User functionality tests
    tests = [
        ("test_user1_access", test_user1_access),
        ("test_add_and_list_users", test_add_and_list_users),
        ("test_user2_access", test_user2_access),
        ("test_master_key_rotation", test_master_key_rotation),
        ("test_user_removal", test_user_removal),
    ]

    for test_name, test_func in tests:
        total += 1
        result = run_test(test_name, test_func, total, total_test_count)
        if result is True:
            passed += 1
        elif result is None:
            total -= 1  # Don't count skipped tests

    # Summary
    # Simple footer
    print()
    width = get_terminal_width()
    print(f"{T.blue}{'─' * width}{T.clear}")

    # Results and status on separate lines, left-aligned
    print(f"{T.bold}Test Results: {passed}/{total} tests passed{T.clear}")

    if passed == total:
        print(f"{T.bold}{T.green}All tests passed! ✅{T.clear}")
        return_code = 0
    else:
        print(f"{T.bold}{T.red}{total - passed} tests failed! ❌{T.clear}")
        return_code = 1

    return return_code


if __name__ == "__main__":
    sys.exit(main())
