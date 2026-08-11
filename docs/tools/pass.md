# `pass` — the Standard Unix Password Manager

## 1. Overview

`pass` (often called "the standard Unix password manager") is a minimal command-line tool, first released by Jason A. Donenfeld in 2012, that embodies the Unix philosophy of composing small, well-understood tools rather than building a monolithic application. At its core `pass` is a POSIX shell script (with a companion `zsh`/`bash` completion set) that wraps two mature, independently-audited pieces of software: **GnuPG (GPG)** for encryption and **git** for versioning and synchronization. `pass` itself contains no cryptographic code — it shells out to `gpg` for every encrypt/decrypt operation and to `git` for every commit, push, or pull. It is licensed under the **GPL-2.0-only** license and distributed as source, making it auditable end-to-end in a way that closed-source, binary-distributed managers like 1Password are not.

Because the on-disk format is just a directory tree of GPG-encrypted files plus an optional git repository, an entire ecosystem of compatible clients has grown around it without requiring a shared protocol beyond "read/write this directory layout":

- **QtPass** — a cross-platform Qt GUI front-end for the `pass` CLI.
- **Android Password Store (APS)** — an Android app that reads the same store, using OpenKeychain or an embedded OpenPGP implementation for decryption and JGit for sync.
- **browserpass** — a browser extension (Chrome/Firefox) with a native-messaging host that fills credentials into web forms directly from the `pass` store.
- **pass-otp**, **pass-tomb**, **pass-import**, **pass-update**, **pass-audit**, and dozens of other shell-script extensions distributed independently and loaded via `pass`'s extension mechanism.

This "just files" design is the central trade-off that distinguishes `pass` from 1Password: there is no vendor server, no proprietary vault format, and no bundled sync service — but also no built-in metadata protection, access-control server, or polished cross-platform UX out of the box.

## 2. Architecture

A `pass` store is a directory (by default `~/.password-store`) that mirrors the logical naming of secrets in its own file-tree structure. Each secret is stored as an individual file named `<path>/<name>.gpg`, e.g. `~/.password-store/Email/work@example.com.gpg`. The plaintext content is typically the secret (e.g., a password) on the first line, followed by arbitrary additional lines of free-form metadata (URLs, usernames, notes, TOTP seeds) — a convention rather than an enforced schema.

Each directory in the tree may contain a `.gpg-id` file listing one or more GPG key IDs/fingerprints (one per line). This file determines the recipient set used when `pass insert` or `pass edit` encrypts a new or updated entry in that directory or any subdirectory that does not itself override `.gpg-id`. This allows a single store to segment secrets by team or project, each encrypted to a different set of recipients (e.g., an `Infra/` subtree encrypted to the ops team's keys, an `HR/` subtree encrypted only to HR).

The entire `~/.password-store` directory can optionally be a git repository (`pass git init`). When it is, every mutating `pass` command (`insert`, `edit`, `rm`, `mv`, `cp`, `generate`) automatically stages and commits the change, giving the store a full linear history of who changed what secret and when (subject to git's own commit-authorship model — see Section 3). `pass git push`/`pull` (or plain `pass git <args>` passthrough) is used to synchronize the store with a remote, which can be any git hosting service or self-hosted git server the user controls.

Extensions live in `$PASS_EXTENSIONS` directories (default `/usr/lib/password-store/extensions` or `~/.password-store/.extensions` with `PASSWORD_STORE_ENABLE_EXTENSIONS=true`) as executable shell scripts named `pass-<subcommand>.bash`; `pass <subcommand>` dispatches to them exactly like a git subcommand dispatch model, which is how `otp`, `tomb`, `import`, `audit`, and other verbs are added without modifying the `pass` core.

## 3. Cryptography & Security Model

All confidentiality and integrity guarantees in `pass` are delegated entirely to GnuPG; `pass` does not implement, configure defaults for, or override GPG's cipher choices beyond what the user's `gpg` configuration (`~/.gnupg/gpg.conf`) specifies. Two modes are possible:

- **Public-key mode** (the default and recommended mode): each secret file is encrypted with `gpg -e` to one or more recipients listed in `.gpg-id`, using OpenPGP public-key encryption (historically RSA, increasingly ECC/Curve25519 with modern GnuPG). Decryption requires the corresponding private key, which is itself normally protected by a passphrase.
- **Symmetric mode**: less commonly used, where `gpg -c` encrypts with a shared passphrase instead of key pairs.

Because `pass` shells out to `gpg` for every operation, it inherits **`gpg-agent`** as its key-caching and passphrase-handling layer. `gpg-agent` runs as a per-user background daemon, caches unlocked private keys in memory for a configurable TTL (`default-cache-ttl`, `max-cache-ttl`), and is responsible for prompting via `pinentry` for the passphrase. `pass` never sees or stores the passphrase itself — that interaction happens entirely between `gpg`/`gpg-agent` and `pinentry`.

Multi-recipient encryption is `pass`'s mechanism for team sharing: adding a colleague's GPG key fingerprint to a `.gpg-id` file and running `pass init --path=<subtree> <id1> <id2> ...` re-encrypts every secret in that subtree to the union of recipients, so each authorized person can decrypt with their own private key — there is no shared master secret to distribute.

**What is *not* encrypted** is the most significant caveat relative to 1Password's vault model: secret **names, directory structure, and the count/size of entries are stored and transmitted in plaintext** as the git tree itself. Anyone with read access to the store (locally, or via the git remote/backups) can see that a user has entries named `Banking/chase.gpg`, `Email/work@example.com.gpg`, etc., even without any GPG key. This is a structural metadata leak, not a bug, and is inherent to the "directory of files" design. Mitigations exist but are opt-in and third-party:

- **pass-tomb** — an extension that stores the entire `.password-store` inside a LUKS-encrypted "tomb" (via the `tomb` tool), closed/opened around usage, hiding the whole tree (including filenames) at rest when the tomb is closed, at the cost of losing git-native diffing while closed.
- Full-disk encryption of the underlying filesystem, which protects at-rest confidentiality but not what is exposed to a git remote.
- Manually flattening or hashing names, which breaks usability and is rarely done.

Additionally, `pass`'s git integration does **not** encrypt commit metadata: commit author name/email, commit timestamps, and commit messages (which by default just say "Add password for ..." including the plaintext entry name) are all stored unencrypted in the git object database and are visible to anyone with repo access, including any git hosting provider used as a remote.

## 4. Protocols

`pass` defines no protocol of its own. All wire/on-disk formats it produces are those of its two dependencies:

- **Encryption**: OpenPGP as specified in **RFC 4880** (and its successor RFC 9580 for newer GnuPG versions), implemented entirely by the external `gpg` binary. `pass` invokes `gpg` via subprocess calls (`gpg -e -r <recipient> ...`, `gpg -d ...`) and parses only exit codes and stdout/stderr text — there is no library linkage or custom serialization.
- **Synchronization**: whatever transport the user's git remote uses — SSH (`git@host:repo.git`), HTTPS with git's smart-HTTP protocol, or the legacy `git://` protocol — entirely governed by git's own protocol implementation and the remote's authentication (SSH keys, HTTPS credentials/tokens). `pass` has no involvement beyond calling `git` as a subprocess.
- **Local IPC**: the only "protocol" surface unique to the cryptographic backend is `gpg-agent`'s local Assuan-protocol IPC socket (typically under `$GNUPGHOME/S.gpg-agent`), used by `gpg` (and thus transitively by `pass`) to request decryption operations and passphrase caching from the agent without re-prompting on every call. This socket is Unix-domain (or a named pipe on Windows via Gpg4win) and is access-controlled by filesystem permissions, not by any authentication protocol of its own.

## 5. Threat Model & Known Limitations

- **Metadata leakage**: as detailed above, filenames and directory structure — effectively a full inventory of "what accounts/systems this user/team has secrets for" — are unencrypted by default and exposed to anyone with read access to the store or its git history, including cloud git hosts. This is the most cited limitation relative to 1Password, whose vault format encrypts item metadata alongside secret data.
- **Reliance on the user's git remote security**: since `pass` treats git purely as a dumb sync/versioning backend, the confidentiality of metadata and the availability/integrity of the encrypted blobs depend entirely on whatever remote (GitHub, GitLab, a self-hosted server) the user chooses and how well they secure it. `pass` provides no guidance or enforcement here.
- **Key management burden**: `pass` places full responsibility for generating, backing up, rotating, and protecting GPG private keys on the user. There is no recovery mechanism, no escrow, and no vendor-assisted account recovery — losing the private key (and any revocation certificate) means permanent loss of access to every secret encrypted to it, with no fallback.
- **No built-in session/2FA model**: because `pass` is not a running service but a stateless CLI acting on flat files, concepts like session timeouts, device authorization, or app-level two-factor login (as in 1Password's account model) do not exist. The only "session" is `gpg-agent`'s cache TTL, which is a convenience feature, not a security boundary designed for multi-user shared-vault access control.
- **Revocation complexity**: removing a team member's access requires editing `.gpg-id` to drop their key and then **re-encrypting every affected secret** (`pass init` re-run over the subtree) so the removed member's key is no longer among the recipients of any ciphertext. Because the old ciphertexts (and their git history) may still exist in prior commits, true revocation of already-shared secrets requires rotating the actual secret values, not just re-encrypting — pass provides no mechanism to guarantee a departed member cannot decrypt already-distributed historical blobs they may have retained.
- **No tamper/integrity guarantees beyond GPG**: OpenPGP provides confidentiality and (with signing) integrity for the ciphertext itself, but `pass` does not sign commits by default, so git history tampering (rewriting who "added" a secret) is possible unless the user separately configures commit signing.

## 6. Sources / References

This chapter is based on `pass`'s public documentation and open-source artifacts:

- The official `pass` project site and manual, `passwordstore.org` (man pages `pass(1)`, `PASSWORD-STORE.md`).
- The `pass` source repository (git.zx2c4.com/password-store), GPL-2.0-only licensed.
- GnuPG project documentation (`gnupg.org`) for `gpg` and `gpg-agent` behavior, including the Assuan IPC protocol used by `gpg-agent`.
- OpenPGP specifications RFC 4880 ("OpenPGP Message Format") and RFC 9580 (its 2024 revision).
- Third-party extension repositories referenced by the `pass` wiki (pass-tomb, pass-otp, pass-import, pass-audit) and community clients (QtPass, Android Password Store, browserpass), each independently maintained and documented in their own repositories.
