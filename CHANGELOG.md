# Changelog

## (Unreleased)

**New features**
- Add `bundle` command to decrypt and output multiple files in a single stream. Each file is prefixed with a header showing its size in the format `-- <size> <filename>`, making it easy to parse programmatically while remaining human-readable. Useful for extracting multiple secrets at once or processing files in scripts.

## 0.2 (2025-09-09)

**Encrypted user secrets**
- `init-user` now generates a passphrase-encrypted keypair (saved as `user-secret.age.enc`).
  to keep the old behavior (plaintext keypair), run `init-user --unencrypted`.
- Add migration command: `migrate encrypt-user-secret` lets v0.1 users convert their
  existing plaintext `user-secret.age` to an encrypted `user-secret.age.enc`.
  Existing unencrypted keypairs continue to work; migration is optional.
- Show a warning when an unencrypted keypair (`user-secret.age`) is used.

**Migration from v0.1 (unencrypted user secrets):**
If you have an existing `user-secret.age` file from v0.1, you can continue using it as-is (you'll see a warning). To migrate to encrypted user secrets for better security:
1. Run `./age-store.py migrate encrypt-user-secret`
2. Enter a strong passphrase when prompted
3. Your plaintext `user-secret.age` will be encrypted and saved as `user-secret.age.enc`
4. The original plaintext file will be deleted
5. Future operations will prompt for your passphrase

**Other changes**
- Add `doctor` command to run health checks.
- Support encrypting and decrypting binary files.
- Add `version` command.
- Add `--user-secret` option to specify custom user secret file paths.
- Command renames: `list-files` → `ls`, `view-file` → `view`, `add-file` → `add`.
- Add access verification to `ls` command to ensure users can only see files they have permission to access.
- Make `add` non-interactive on conflict: it now fails if the target file already exists and suggests using `--force`; add `--force` flag to allow overwrite.

## 0.1 (Initial Release)

Core commands:
- init-user
- show-pubkey
- list-files
- view-file
- add-file
- admin bootstrap
- admin add-user
- admin remove-user
- admin rotate-master-key
- admin list-users
