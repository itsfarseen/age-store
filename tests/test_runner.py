#!/usr/bin/env python3
"""
Age Store CLI Test Runner
"""

import argparse
import os
import shutil
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
TMP_DATA_DIR = TESTS_DIR / "tmp-data"
AGE_STORE_SCRIPT = TESTS_DIR.parent / "age-store.py"

# Global verbose flag
verbose = False


def cleanup_and_setup():
    """Clean up tmp-data folder and create test directories."""
    if TMP_DATA_DIR.exists():
        shutil.rmtree(TMP_DATA_DIR)

    TMP_DATA_DIR.mkdir(exist_ok=True)
    (TMP_DATA_DIR / "store0").mkdir(exist_ok=True)
    (TMP_DATA_DIR / "store1").mkdir(exist_ok=True)
    (TMP_DATA_DIR / "store2").mkdir(exist_ok=True)


def run_age_store_command(
    store_path, command, capture_output=True, input_text=None, description=None
):
    """Run age-store.py command in specified store directory."""
    original_cwd = os.getcwd()
    try:
        os.chdir(store_path)
        cmd = [str(AGE_STORE_SCRIPT)] + command

        # Print description if verbose mode is enabled
        if verbose and description:
            print(f"\n◼ {description}")

        # Print the command being executed
        store_name = Path(store_path).name
        args_str = " ".join(command)
        print(
            f"{T.blue}{store_name}:{T.clear} {T.yellow}age-store.py {args_str}{T.clear}",
            end="\r",
        )

        if capture_output:
            result = subprocess.run(
                cmd, capture_output=True, text=True, input=input_text
            )

            # Rewrite the line with success/failure color
            if result.returncode == 0:
                command_color = T.green
            else:
                command_color = T.red

            print(
                f"{T.blue}{store_name}:{T.clear} {command_color}age-store.py {args_str}{T.clear}"
            )

            # Print output if verbose mode is enabled
            if verbose and result.stdout.strip():
                print_with_left_border(
                    result.stdout.rstrip(), border_color=T.grey, text_color=T.grey
                )

            return result.returncode, result.stdout, result.stderr
        else:
            result = subprocess.run(cmd, input=input_text, text=True)
            return result.returncode, "", ""
    finally:
        os.chdir(original_cwd)


def verbose_check(description, condition):
    """Print check description and result if verbose mode is enabled, return condition value."""
    if verbose:
        if condition:
            print(f"{T.green}▸ check {description} [OK]{T.clear}")
        else:
            print(f"{T.red}▸ check {description} [FAIL]{T.clear}")
    return condition


def create_test_file(store_path, filename, content):
    """Create a test file in the store directory."""
    test_file_path = store_path / filename
    with open(test_file_path, "w") as f:
        f.write(content)
    return test_file_path


def extract_public_key(output):
    """Extract age public key from command output, ignoring warnings."""
    lines = output.strip().split("\n")
    for line in lines:
        line = line.strip()
        # Look for line starting with "age1" directly
        if line.startswith("age1"):
            return line
    return None


def copy_store_files(src_store, dest_store, exclude_user_secret=True):
    """Copy store files from src to dest, optionally excluding user-secret files."""
    src_path = Path(src_store)
    dest_path = Path(dest_store)

    for item in src_path.iterdir():
        if exclude_user_secret and item.name in (
            "user-secret.age",
            "user-secret.age.enc",
        ):
            continue

        if item.is_file():
            shutil.copy2(item, dest_path)
        elif item.is_dir():
            dest_subdir = dest_path / item.name
            if dest_subdir.exists():
                shutil.rmtree(dest_subdir)
            shutil.copytree(item, dest_subdir)


def test_init_and_bootstrap():
    """Test basic init-user and admin bootstrap functionality."""
    store0_path = TMP_DATA_DIR / "store0"

    # Test init-user
    returncode, stdout, stderr = run_age_store_command(
        store0_path,
        ["init-user", "--unencrypted"],
        description="initialize user with unencrypted private key",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"init-user failed: {stderr}"

    if not verbose_check(
        "output contains completion message",
        "User initialization complete (unencrypted)" in stdout,
    ):
        return False, f"init-user output unexpected: {stdout}"

    # Check that user-secret.age was created
    user_secret_file = store0_path / "user-secret.age"
    if not verbose_check("user-secret.age file was created", user_secret_file.exists()):
        return False, "user-secret.age not created"

    # Get public key for bootstrap
    returncode, pubkey_stdout, stderr = run_age_store_command(
        store0_path, ["show-pubkey"], description="get the user's public key"
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"show-pubkey failed: {stderr}"

    pubkey = extract_public_key(pubkey_stdout)
    if not verbose_check("output contains valid age1 public key", pubkey is not None):
        return False, f"No valid public key found in output: {pubkey_stdout}"

    # Test bootstrap
    returncode, stdout, stderr = run_age_store_command(
        store0_path,
        ["admin", "bootstrap", "user1"],
        description="bootstrap the store with user1",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"bootstrap failed: {stderr}"

    # Check that store directory and files were created
    if not verbose_check(
        "store directory was created", (store0_path / "store").exists()
    ):
        return False, "store directory not created"

    if not verbose_check(
        "users.json was created", (store0_path / "users.json").exists()
    ):
        return False, "users.json not created"

    if not verbose_check(
        "master-key.age.enc was created", (store0_path / "master-key.age.enc").exists()
    ):
        return False, "master-key.age.enc not created"

    return True, None


def setup_stores():
    """Set up store1 (fully initialized) and store2 (init-user only)."""
    store1_path = TMP_DATA_DIR / "store1"
    store2_path = TMP_DATA_DIR / "store2"

    # Setup store1
    returncode, stdout, stderr = run_age_store_command(
        store1_path,
        ["init-user", "--unencrypted"],
        description="initialize store1 user",
    )
    if returncode != 0:
        raise RuntimeError(f"Failed to init store1: {stderr}")

    returncode, pubkey_stdout, stderr = run_age_store_command(
        store1_path, ["show-pubkey"], description="get store1 public key"
    )
    if returncode != 0:
        raise RuntimeError(f"Failed to get store1 pubkey: {stderr}")

    store1_pubkey = extract_public_key(pubkey_stdout)
    if not store1_pubkey:
        raise RuntimeError(
            f"No valid public key found in store1 output: {pubkey_stdout}"
        )
    returncode, stdout, stderr = run_age_store_command(
        store1_path,
        ["admin", "bootstrap", "user1"],
        description="bootstrap store1 with user1",
    )
    if returncode != 0:
        raise RuntimeError(f"Failed to bootstrap store1: {stderr}")

    # Setup store2 (init-user only)
    returncode, stdout, stderr = run_age_store_command(
        store2_path,
        ["init-user", "--unencrypted"],
        description="initialize store2 user",
    )
    if returncode != 0:
        raise RuntimeError(f"Failed to init store2: {stderr}")

    return store1_pubkey


def test_store1_add():
    """Test adding files to store1."""
    store1_path = TMP_DATA_DIR / "store1"

    # Create test file
    test_file = create_test_file(store1_path, "test-secret.txt", "secret content")

    # Add file to store
    returncode, stdout, stderr = run_age_store_command(
        store1_path,
        ["add", test_file.name],
        description="add test-secret.txt to the encrypted store",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"add command failed: {stderr}"

    # Check that encrypted file exists
    encrypted_file = store1_path / "store" / "test-secret.txt.enc"
    if not verbose_check("encrypted file was created", encrypted_file.exists()):
        return False, "Encrypted file was not created"

    # Clean up test file
    test_file.unlink()

    return True, None


def test_store1_view():
    """Test viewing files from store1."""
    store1_path = TMP_DATA_DIR / "store1"

    # View the file we added
    returncode, stdout, stderr = run_age_store_command(
        store1_path,
        ["view", "test-secret.txt"],
        description="view the encrypted test-secret.txt file",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"view command failed: {stderr}"

    if not verbose_check("output contains secret content", "secret content" in stdout):
        return False, f"File content not found in output: {stdout}"

    return True, None


def test_store1_ls():
    """Test listing files in store1."""
    store1_path = TMP_DATA_DIR / "store1"

    returncode, stdout, stderr = run_age_store_command(
        store1_path, ["ls"], description="list all files in the store"
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"ls command failed: {stderr}"

    if not verbose_check(
        "output contains test-secret.txt", "test-secret.txt" in stdout
    ):
        return False, f"Added file not found in ls output: {stdout}"

    return True, None


def test_add_user():
    """Test adding store2 user to store1."""
    store1_path = TMP_DATA_DIR / "store1"
    store2_path = TMP_DATA_DIR / "store2"

    # Get store2's public key
    returncode, pubkey_stdout, stderr = run_age_store_command(
        store2_path, ["show-pubkey"], description="get store2's public key"
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get store2 pubkey: {stderr}"

    store2_pubkey = extract_public_key(pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", store2_pubkey is not None
    ):
        return False, f"No valid public key found in store2 output: {pubkey_stdout}"

    # Add store2 user to store1
    returncode, stdout, stderr = run_age_store_command(
        store1_path,
        ["admin", "add-user", "user2", store2_pubkey],
        description="add user2 to store1's user list",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"add-user failed: {stderr}"

    return True, None


def test_list_users():
    """Test listing users after adding both users."""
    store1_path = TMP_DATA_DIR / "store1"

    # List users in store1
    returncode, stdout, stderr = run_age_store_command(
        store1_path, ["admin", "list-users"], description="list all users"
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"list-users failed: {stderr}"

    # Should contain both users
    if not verbose_check("output contains user1", "user1" in stdout):
        return False, f"user1 not found in list-users output: {stdout}"

    if not verbose_check("output contains user2", "user2" in stdout):
        return False, f"user2 not found in list-users output: {stdout}"

    # Should show exactly 2 users
    lines = stdout.strip().split("\n")
    # Count lines that contain user entries (skip header lines)
    user_count = sum(
        1 for line in lines if line.strip() and ("user1" in line or "user2" in line)
    )

    if user_count != 2:
        return False, f"Expected exactly 2 users, found {user_count}: {stdout}"

    return True, None


def test_store2_access_after_copy():
    """Test that store2 can access files after copying store data."""
    store1_path = TMP_DATA_DIR / "store1"
    store2_path = TMP_DATA_DIR / "store2"

    # Store original store2 pubkey for verification
    returncode, original_pubkey_stdout, stderr = run_age_store_command(
        store2_path, ["show-pubkey"], description="get original store2 public key"
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get original store2 pubkey: {stderr}"

    original_pubkey = extract_public_key(original_pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", original_pubkey is not None
    ):
        return False, f"No valid original pubkey found: {original_pubkey_stdout}"

    # Copy store1 files to store2 (excluding user-secret)
    copy_store_files(store1_path, store2_path, exclude_user_secret=True)

    # Verify store2 pubkey hasn't changed
    returncode, current_pubkey_stdout, stderr = run_age_store_command(
        store2_path, ["show-pubkey"], description="verify store2 public key after copy"
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get current store2 pubkey: {stderr}"

    current_pubkey = extract_public_key(current_pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", current_pubkey is not None
    ):
        return False, f"No valid current pubkey found: {current_pubkey_stdout}"

    if not verbose_check(
        "public key unchanged after copy", original_pubkey == current_pubkey
    ):
        return (
            False,
            f"Store2 pubkey changed after copy: {original_pubkey} -> {current_pubkey}",
        )

    # Test that store2 can now access the files
    returncode, stdout, stderr = run_age_store_command(
        store2_path, ["ls"], description="list files from store2 after copy"
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"store2 ls failed: {stderr}"

    if not verbose_check(
        "output contains test-secret.txt", "test-secret.txt" in stdout
    ):
        return False, f"store2 cannot see files: {stdout}"

    # Test view
    returncode, stdout, stderr = run_age_store_command(
        store2_path,
        ["view", "test-secret.txt"],
        description="view test-secret.txt from store2",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"store2 view failed: {stderr}"

    if not verbose_check("output contains secret content", "secret content" in stdout):
        return False, f"store2 cannot read file content: {stdout}"

    # Test add
    test_file = create_test_file(store2_path, "store2-secret.txt", "store2 content")
    returncode, stdout, stderr = run_age_store_command(
        store2_path,
        ["add", test_file.name],
        description="add store2-secret.txt from store2",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"store2 add failed: {stderr}"

    test_file.unlink()

    return True, None


def test_master_key_rotation():
    """Test master key rotation and file re-encryption."""
    store1_path = TMP_DATA_DIR / "store1"
    store2_path = TMP_DATA_DIR / "store2"

    # Get original encrypted file content
    encrypted_file = store1_path / "store" / "test-secret.txt.enc"
    with open(encrypted_file, "rb") as f:
        original_content = f.read()

    # Rotate master key in store1
    returncode, stdout, stderr = run_age_store_command(
        store1_path,
        ["admin", "rotate-master-key"],
        description="rotate the master key and re-encrypt all files",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"rotate-master-key failed: {stderr}"

    # Verify encrypted file content changed
    with open(encrypted_file, "rb") as f:
        new_content = f.read()

    if original_content == new_content:
        return False, "Encrypted file content didn't change after key rotation"

    # Store original store2 pubkey
    returncode, original_pubkey_stdout, stderr = run_age_store_command(
        store2_path,
        ["show-pubkey"],
        description="get store2 public key before rotation",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get store2 pubkey before copy: {stderr}"

    original_pubkey = extract_public_key(original_pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", original_pubkey is not None
    ):
        return False, f"No valid original pubkey found: {original_pubkey_stdout}"

    # Copy rotated store1 files to store2
    copy_store_files(store1_path, store2_path, exclude_user_secret=True)

    # Verify store2 pubkey hasn't changed
    returncode, current_pubkey_stdout, stderr = run_age_store_command(
        store2_path,
        ["show-pubkey"],
        description="verify store2 public key after rotation copy",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get store2 pubkey after copy: {stderr}"

    current_pubkey = extract_public_key(current_pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", current_pubkey is not None
    ):
        return (
            False,
            f"No valid current pubkey found after copy: {current_pubkey_stdout}",
        )

    if not verbose_check(
        "public key unchanged after rotation", original_pubkey == current_pubkey
    ):
        return (
            False,
            f"Store2 pubkey changed after copy: {original_pubkey} -> {current_pubkey}",
        )

    # Test that both store1 and store2 can still access files
    for store_name, store_path in [("store1", store1_path), ("store2", store2_path)]:
        returncode, stdout, stderr = run_age_store_command(
            store_path,
            ["view", "test-secret.txt"],
            description=f"verify {store_name} can access file after rotation",
        )
        if not verbose_check("command succeeded", returncode == 0):
            return False, f"{store_name} cannot access file after rotation: {stderr}"

        if not verbose_check(
            "output contains secret content", "secret content" in stdout
        ):
            return (
                False,
                f"{store_name} file content incorrect after rotation: {stdout}",
            )

    return True, None


def test_user_removal():
    """Test removing user access and verifying access is lost."""
    store1_path = TMP_DATA_DIR / "store1"
    store2_path = TMP_DATA_DIR / "store2"

    # Store original store2 pubkey
    returncode, original_pubkey_stdout, stderr = run_age_store_command(
        store2_path, ["show-pubkey"], description="get store2 public key before removal"
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get store2 pubkey: {stderr}"

    original_pubkey = extract_public_key(original_pubkey_stdout)
    if not verbose_check(
        "output contains valid age1 public key", original_pubkey is not None
    ):
        return False, f"No valid original pubkey found: {original_pubkey_stdout}"

    # Remove store2 user from store1
    returncode, stdout, stderr = run_age_store_command(
        store1_path,
        ["admin", "remove-user", "user2"],
        description="remove user2 from store1",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"remove-user failed: {stderr}"

    # Copy store1 files to store2 (excluding user-secret)
    copy_store_files(store1_path, store2_path, exclude_user_secret=True)

    # Verify store2 pubkey hasn't changed
    returncode, current_pubkey_stdout, stderr = run_age_store_command(
        store2_path,
        ["show-pubkey"],
        description="verify store2 public key after removal",
    )
    if not verbose_check("command succeeded", returncode == 0):
        return False, f"Failed to get store2 pubkey after removal: {stderr}"

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
            f"Store2 pubkey changed after copy: {original_pubkey} -> {current_pubkey}",
        )

    # Test that store2 has lost access
    returncode, stdout, stderr = run_age_store_command(
        store2_path,
        ["view", "test-secret.txt"],
        description="try to view test-secret.txt from store2 (should fail)",
    )
    if not verbose_check("command failed as expected", returncode != 0):
        return False, "Store2 can still access files after user removal"

    # Test that store2 cannot add files
    test_file = create_test_file(
        store2_path, "unauthorized-secret.txt", "unauthorized content"
    )
    returncode, stdout, stderr = run_age_store_command(
        store2_path,
        ["add", test_file.name],
        description="try to add unauthorized-secret.txt from store2 (should fail)",
    )
    if not verbose_check("command failed as expected", returncode != 0):
        return False, "Store2 can still add files after user removal"

    test_file.unlink()

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

    # Track test results
    passed = 0
    total = 0

    # Calculate total tests
    total_test_count = 9  # Update this if you add/remove tests

    # Basic init and bootstrap tests
    total += 1
    result = run_test(
        "test_init_and_bootstrap", test_init_and_bootstrap, total, total_test_count
    )
    if result is True:
        passed += 1
    elif result is None:
        total -= 1  # Don't count skipped tests

    # Setup stores for remaining tests
    try:
        print("Setting up test stores...")
        store1_pubkey = setup_stores()
    except Exception as e:
        print(f"Failed to setup stores: {e}")
        sys.exit(1)

    # Store1 functionality tests
    tests = [
        ("test_store1_add", test_store1_add),
        ("test_store1_view", test_store1_view),
        ("test_store1_ls", test_store1_ls),
        ("test_add_user", test_add_user),
        ("test_list_users", test_list_users),
        ("test_store2_access_after_copy", test_store2_access_after_copy),
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
