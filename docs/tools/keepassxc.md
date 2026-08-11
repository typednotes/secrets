# KeePass / KeePassXC

## 1. Overview

KeePass is a family of local, file-based password managers whose lineage
splits into two active branches. **KeePass 1.x** (renamed KeePassX on
non-Windows platforms) and **KeePass 2.x** are the original .NET/Mono
implementations by Dominik Reichl, first released in the early 2000s.
KeePass 2.x introduced the KDBX file format (an evolution of the original
KDB format) and a plugin framework, but remained tightly coupled to
Windows and Mono for cross-platform use.

**KeePassXC** ("KeePass Cross-platform Community edition") is a 2016 fork
of KeePassX (itself a Qt-based port of KeePass 1.x) created because
KeePassX's development had stalled and the community wanted a
cross-platform, actively maintained client with modern features —
browser integration, YubiKey support, TOTP generation, and CLI tooling —
without depending on Mono. KeePassXC is written in C++/Qt and today is
the most actively developed member of the family, broadly compatible
with the KDBX 4 format also used by KeePass 2.x.

Licensing is GPL-2.0-or-later for the core KeePass code lineage, with
KeePassXC distributed under **GPL-2.0/GPL-3.0** (dual/either, depending
on component) with some components under other permissive licenses.
There is no commercial entity behind KeePassXC; it is a volunteer
open-source project.

The defining philosophy of the whole family, in contrast to 1Password,
Bitwarden, or other cloud-native vaults, is **local-file-only storage
with no first-party sync or hosting service**. The vault is a single
encrypted file (`.kdbx`) that lives wherever the user puts it — a local
disk, an external drive, or a folder synced by some other tool. KeePass
and KeePassXC ship no server, no account system, and no telemetry. This
maximizes user control and auditability (the encrypted blob format is
open and documented) but pushes all synchronization, backup, and
multi-device consistency problems onto the user.

## 2. Architecture

### Single-file database model

The core data model is deliberately simple: one KDBX file represents one
database, structured internally as a tree of groups (folders) containing
entries (title, username, password, URL, notes, custom fields,
attachments, TOTP seed, icon). The entire tree, once decrypted, is held
in memory as an XML document (in KDBX 4, still XML-based internally,
though wrapped in a binary container with a different header/inner
structure than KDBX 3.x). There is no client-server split, no
per-request network calls, and no partial decryption — opening the
database means decrypting the whole file into memory at once.

### Application structure

KeePassXC is a single desktop application (Qt/C++) with:

- A **core library** (`libkeepassx` internally) that implements KDBX
  parsing/serialization, cryptography, and the entry/group data model.
- A **GUI layer** for browsing, editing, auto-type, and settings.
- A **CLI tool** (`keepassxc-cli`) that operates on the same KDBX files
  headlessly, useful for scripting.
- A **browser integration component** (KeePassXC-Browser) that exposes a
  local IPC channel to companion browser extensions.
- Optional secondary databases can be attached/merged, and KeePassXC
  supports database merging (three-way merge of XML entry trees) as a
  manual conflict-resolution mechanism.

### Plugin / browser-integration architecture

Unlike KeePass 2.x, which relies on a rich third-party .NET plugin
ecosystem (loaded in-process via reflection), KeePassXC deliberately
does **not** support arbitrary binary plugins, citing security risk.
Instead it exposes a small number of built-in, audited integrations
(browser support, SSH agent support via `KeeAgent`-equivalent
functionality, YubiKey challenge-response, Secret Service D-Bus API
emulation on Linux). Browser integration is implemented as a local
socket/named-pipe server inside the KeePassXC process that a separate,
independently distributed browser extension connects to — this keeps
the trust boundary between "arbitrary web-extension code" and "the
process holding decrypted secrets" enforced by OS-level IPC rather than
in-process plugin loading.

### Sync is delegated, not built-in

Because there is no first-party server, users who want multi-device
access sync the `.kdbx` file themselves using generic file-sync tools:
Dropbox, Google Drive, Syncthing, Nextcloud, a USB stick, or — via the
**KeeShare** extension — git or other version-controlled/shared
transports. This has an important consequence: **none of these
transports understand the KDBX format**, so they perform sync at the
byte/file level. If two devices modify the same database while offline
and the sync tool cannot merge them, the result is either a last-writer-
wins overwrite or a "conflicted copy" file that the user must resolve
manually (KeePassXC's database-merge feature can help reconcile two
divergent copies, but this is a manual, user-invoked operation, not an
automatic feature of the sync layer). There is no operational
transform, no CRDT, and no server-mediated locking — the append-only,
field-level conflict resolution that a client-server vault like
Bitwarden or 1Password gets "for free" from its backend does not exist
here.

## 3. Cryptography & security model

### KDBX 4 file format

KDBX 4 (the current generation, introduced with KeePass 2.35+ and
supported natively by KeePassXC) restructured the file relative to KDBX
3.x to close cryptographic weaknesses and add algorithm agility. A KDBX
4 file consists of:

1. A **plaintext outer header** containing the format version, cipher
   ID, compression flag (Gzip is optional before encryption), the KDF
   parameters (algorithm + salt/memory/iterations/parallelism settings
   encoded as a VariantDictionary), and a master seed.
2. A **header HMAC-SHA-256** value computed over the header bytes, keyed
   from the derived master key, allowing header tampering to be
   detected *before* attempting decryption.
3. The **encrypted body**, itself split into HMAC-authenticated blocks
   (HMAC-SHA-256 per block) so that ciphertext tampering anywhere in the
   file is detected during decryption rather than silently producing
   garbage — this closed a padding-oracle-style weakness present in
   KDBX 3.1's CBC-with-trailing-hash construction.
4. Inside the decrypted body, an **inner header** specifies the inner
   stream cipher used to additionally protect specific "protected"
   fields (typically passwords) in memory and in the decrypted XML, plus
   any binary attachments.

### Master key composition

The key used to decrypt a database is derived from a combination of
**key sources**, not necessarily just a password:

- A user **password/passphrase** (optional but typical).
- A **key file** — an arbitrary file (or a KeePass-generated
  random-key XML file) whose contents are hashed into the key material;
  losing this file is as fatal as losing the password.
- The **current Windows user account** (KeePass 2.x only; ties the key
  to a Windows DPAPI-protected secret, and is not portable off that
  machine/account).
- A **YubiKey (or compatible HMAC-SHA1 challenge-response token)** as an
  additional hardware factor: the app sends a challenge to the key, and
  the HMAC-SHA1 response is folded into the composite key.

These sources are concatenated/hashed together (SHA-256) to form a
composite key, which is then run through a **key derivation function**
before use as the actual cipher key.

### KDF and cipher choices

KDBX 4 supports pluggable KDFs, selectable per database:

- **Argon2d** (the KDBX 4 default in KeePassXC for a long time) and
  **Argon2id** — memory-hard KDFs resistant to GPU/ASIC brute-forcing,
  configurable by memory (MiB), iterations, and parallelism.
- **AES-KDF** (AES-256 used as a KDF via repeated single-block
  encryption, i.e. the KDBX 3.x-style approach), retained for legacy
  compatibility and configurable iteration count.

The KDF output becomes the key for the outer **block cipher**, user
selectable among:

- **AES-256** (CBC mode) — the long-standing default.
- **ChaCha20** — a modern stream cipher option added for performance and
  as an AES alternative.
- **Twofish** — retained mainly for legacy/compatibility reasons.

**Integrity**: as noted above, KDBX 4 authenticates both the header and
the encrypted body via HMAC-SHA-256, rather than relying on a plain hash
of the plaintext (KDBX 3.x's weaker approach).

**Inner stream cipher**: within the decrypted plaintext, individual
"protected" field values (passwords, and optionally other fields) are
further obscured using an inner stream cipher — historically **Salsa20**,
now **ChaCha20** by default in KDBX 4 — primarily to reduce the chance
of secrets appearing in cleartext in memory dumps or being logged
inadvertently by the XML layer, rather than as a primary confidentiality
boundary (that role belongs to the outer cipher).

### One encrypted blob vs. per-item encryption

A structurally important difference from Bitwarden-style vaults is that
**the entire KDBX file is a single encrypted unit**. There is no
per-item symmetric key wrapped by a master key, no per-record envelope —
decrypting the file means decrypting (and authenticating) the whole
database at once. This is simpler and arguably more conservative
cryptographically (fewer moving parts, no per-item key management), but
it also means there is no notion of granular, partial, or field-level
re-encryption without rewriting the whole file, and no way to share a
subset of entries without either exporting them or using KeeShare's
separate-file mechanism.

## 4. Protocols

KeePass/KeePassXC is fundamentally **not a networked application** —
there is no client-server wire protocol for core vault operations,
because there is no server. The "protocols" that exist are local IPC
mechanisms and file-based sharing formats:

- **KeePassXC-Browser protocol**: the desktop app runs a local socket
  (Unix domain socket / named pipe, depending on OS) that a companion
  browser extension (for Firefox, Chrome, and other Chromium-based
  browsers) connects to. Communication is encrypted end-to-end at the
  application layer using a **NaCl/libsodium `crypto_box`
  (Curve25519-XSalsa20-Poly1305) construction**: the extension and the
  desktop app each generate an ephemeral key pair, exchange public keys
  during a one-time pairing/association step (the user approves the
  connection in the KeePassXC UI, and the resulting association key is
  persisted for future sessions), and then every subsequent request/
  response (credential retrieval, autofill, TOTP fetch) is sealed as a
  NaCl box, independent of the OS-level socket's own access controls.
  This gives confidentiality and authentication of the extension-to-app
  channel even though it runs over what is otherwise an unauthenticated
  local transport.
- **Secret Service D-Bus API**: on Linux, KeePassXC can expose entries
  through the freedesktop.org Secret Service specification, allowing
  other applications (e.g. `libsecret`-based apps) to request secrets
  through the standard D-Bus interface instead of a proprietary API.
- **KeeShare**: an extension for sharing parts of a database (or an
  entire group) with other users or devices via a separate, independently
  encrypted/signed container file, distributed through whatever
  out-of-band transport the user chooses — commonly a shared git
  repository, but any file-sync mechanism works. KeeShare containers can
  be signed and/or encrypted, but — consistent with the project's
  general architecture — the transport itself (git, Syncthing, etc.) is
  entirely out of scope for KeePassXC; it only guarantees the
  confidentiality/integrity of the container's contents, not delivery,
  ordering, or conflict resolution.
- **SSH agent protocol**: KeePassXC can act as an SSH agent, exposing
  private keys stored in entries over the standard SSH agent Unix socket
  protocol, so it can be used as a drop-in replacement for `ssh-agent`.

No cloud API, REST endpoint, or push/sync protocol exists in the core
product, by design.

## 5. Threat model & known limitations

- **Single point of failure**: the entire vault is one file protected by
  one composite key. Compromise of the master password/key file (e.g.
  keylogging, keyfile theft, or a weak/reused master password) yields
  the entire database at once — there is no compartmentalization between
  entries the way per-item envelope encryption might provide.
- **Key file handling risk**: key files are ordinary files with no
  special OS protection; if synced or backed up alongside (or instead
  of) the database, they can defeat the extra factor they're meant to
  provide. Losing the key file (without a password fallback) permanently
  locks the database — there is no recovery mechanism, by design (no
  vendor holds an escrow key).
- **No built-in secure sync/versioning**: since synchronization is
  entirely delegated to third-party tools, the user must trust and
  correctly configure whatever transport they choose. A misconfigured or
  compromised sync provider (e.g. a shared Dropbox folder with the wrong
  permissions) becomes part of the vault's trust boundary even though
  KeePassXC itself never contacts it. Conflict handling is manual;
  careless resolution of "conflicted copy" files can silently discard
  edits.
- **Memory protection**: KeePassXC attempts to reduce the exposure of
  secrets in RAM — locking memory pages against swapping where the OS
  allows it, keeping protected fields obscured behind the inner stream
  cipher until actually displayed, and clearing sensitive buffers after
  use — but these are best-effort mitigations against a fundamentally
  hard problem (a sufficiently privileged local attacker, a coredump, a
  hibernation file, or a debugger attached to the process can still
  recover secrets while the database is unlocked).
- **Clipboard clearing**: copied passwords are automatically cleared
  from the OS clipboard after a configurable timeout, mitigating but not
  eliminating clipboard-sniffing malware and clipboard-history features
  in modern OSes/desktop environments that may retain copies elsewhere.
- **Auto-type risks**: the auto-type feature simulates keystrokes into
  the foreground window matched by title/URL heuristics. This is
  convenient but carries risks: a malicious or misconfigured target
  window could receive credentials intended for a different application
  ("auto-type injection"), and because it works by synthesizing
  keyboard events, any keylogger present on the system (hardware or
  software) captures the credential exactly as if it had been typed
  manually — auto-type does not defend against keylogging the way a
  browser-extension-based fill (which can use non-keystroke injection)
  sometimes can.
- **No phishing-domain binding for auto-type**: unlike browser-extension
  autofill (KeePassXC-Browser) which matches the page's actual origin,
  window-title-based auto-type matching is comparatively weak and can be
  spoofed by a window with a similar title.

## 6. Sources / references

This chapter is based on publicly available KeePass and KeePassXC
documentation and open-source code, including the KeePassXC user guide
and technical FAQ, the KDBX 4 file format description maintained by the
KeePass/KeePassXC projects, the KeePassXC-Browser protocol
documentation and source, and the published source code of KeePassXC
(GPL-2.0/GPL-3.0) and the original KeePass project (GPL-2.0-or-later).
No specific version numbers or CVE identifiers are cited here beyond
general format-generation references (KDBX 3.x vs. KDBX 4), since exact
release histories should be verified against current upstream
documentation before being relied upon.
