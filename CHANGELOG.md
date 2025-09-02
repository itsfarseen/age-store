# Changelog

## 0.2 (2025-09-02)

Changes to init-user:
- Default now generates a passphrase-encrypted keypair (saved as `user-secret.age.enc`).
- To keep the old behavior (plaintext keypair), run `init-user --unencrypted`.

Other changes:
- Show a warning when an unencrypted keypair (`user-secret.age`) is used.
- Support encrypting and decrypting binary files.
- Add `version` command.

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
