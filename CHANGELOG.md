# Changelog

## 0.2 (2025-09-04)

**Encrypted user secrets**
- `init-user` now generates a passphrase-encrypted keypair (saved as `user-secret.age.enc`).
  to keep the old behavior (plaintext keypair), run `init-user --unencrypted`.
- Add migration command: `migrate encrypt-user-secret` lets v0.1 users convert their
  existing plaintext `user-secret.age` to an encrypted `user-secret.age.enc`.
  Existing unencrypted keypairs continue to work; migration is optional.
- Show a warning when an unencrypted keypair (`user-secret.age`) is used.

**Other changes**
- Add `doctor` command to run health checks.
- Support encrypting and decrypting binary files.
- Add `version` command.
- Add `--user-secret` option to specify custom user secret file paths.
- Command renames: `list-files` → `ls`, `view-file` → `view`, `add-file` → `add`.
- Add access verification to `ls` command to ensure users can only see files they have permission to access.

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
