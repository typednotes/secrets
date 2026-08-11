# HashiCorp Vault

## 1. Overview

HashiCorp Vault occupies a fundamentally different niche than end-user password
managers like 1Password, Bitwarden, or KeePass. Where those tools are built
around a human unlocking a personal or shared vault of credentials through a
GUI or browser extension, Vault is infrastructure software: a server-based
system for managing *machine-to-machine* and operator secrets at the scale of
a fleet, a data center, or a cloud account. It has no concept of a "shared
family vault" or a browser autofill experience; instead it exposes an API that
applications, CI/CD pipelines, and operators authenticate against to obtain
tightly scoped, often short-lived, credentials.

Licensing history matters for anyone evaluating Vault today. The Vault open
source project was originally released under the Mozilla Public License 2.0
(MPL-2.0). In August 2023, HashiCorp relicensed most of its projects,
including Vault, from MPL-2.0 to the Business Source License (BUSL 1.1), a
source-available but not OSI-approved license that restricts competing
commercial use. This move prompted the Linux Foundation to host a community
fork, **OpenBao**, which continues development of the pre-relicensing Vault
codebase under the original open-source MPL-2.0 terms. Organizations that
require a strictly open-source license (rather than source-available) should
evaluate OpenBao rather than upstream Vault.

Typical Vault use cases center on reducing standing secret material:

- **Dynamic database credentials** — Vault generates short-lived,
  per-request database usernames/passwords on demand and revokes them
  automatically, rather than distributing a long-lived shared password.
- **PKI-as-a-service** — Vault can act as an internal certificate authority,
  issuing short-lived TLS certificates to services without an operator ever
  touching a private key.
- **Encryption as a service** — the `transit` secrets engine lets
  applications delegate encryption/decryption/signing operations to Vault
  without ever handling the raw encryption keys themselves.

This is the "secrets management" sense of the term referenced throughout this
project's documentation: infrastructure credential lifecycle management, not
personal password storage.

## 2. Architecture

Vault's architecture separates the request-handling core from a pluggable
**storage backend**. The storage backend is treated as untrusted, encrypted
blob storage — it never sees plaintext secrets. Supported backends include
Vault's own **Raft integrated storage** (a built-in Raft consensus
implementation that also provides HA coordination, eliminating the need for
an external key-value store), HashiCorp Consul, and various cloud object
stores. Raft integrated storage is the modern default and is what most new
deployments use, since it collapses storage and HA leader election into a
single component.

At the heart of the request path is the **security barrier**, a layer that
encrypts and authenticates every piece of data before it is written to
storage and decrypts it on read. The barrier is guarded by the **seal**:
when a Vault server starts (or restarts), it is *sealed* and cannot perform
any cryptographic operations or serve secrets until it is *unsealed*. Two
unseal mechanisms are supported:

- **Shamir's Secret Sharing** — the barrier's root key is split into *n*
  key shares, of which a threshold *t* must be presented to reconstruct it
  (a classic `t-of-n` scheme). Operators each hold one share.
- **Auto-unseal** — the root key is instead wrapped by an external KMS
  (AWS KMS, GCP Cloud KMS, Azure Key Vault, or an HSM via PKCS#11), so the
  server can unseal itself automatically by calling out to that service on
  startup, removing the need for humans to enter key shares. Recovery keys
  (still Shamir-based) remain for administrative operations like generating
  a new root token.

Functionality inside Vault is organized into two plugin systems:

- **Secrets engines** are mounted at a path (e.g. `database/`, `pki/`,
  `transit/`, `kv/`) and each implement their own logic for generating,
  storing, or brokering a particular class of secret.
- **Auth methods** are likewise mounted at a path (e.g. `auth/ldap`,
  `auth/kubernetes`, `auth/approle`) and are responsible for verifying an
  external identity claim and mapping it to a Vault **policy**.

**Policies** are ACL documents written in HCL/JSON that grant or deny
capabilities (`read`, `create`, `update`, `delete`, `list`, `sudo`) on path
patterns. Every authenticated caller's effective permissions are the union of
the policies attached to its token or identity.

**Namespaces**, available in Vault Enterprise, provide tenant isolation
within a single cluster — separate policy, auth, and secrets-engine trees per
namespace, useful for multi-team or multi-customer deployments.

For availability, Vault runs as a cluster with a single active node and
standby nodes that forward requests (or serve read-only replicas of certain
data) — Raft integrated storage provides this HA coordination natively.
Enterprise adds **Performance Replication** (fan-out of secrets/config to
secondary clusters, e.g. across regions) and **Disaster Recovery
Replication** (a warm standby cluster for failover), both operating
asynchronously over Vault's internal replication protocol.

## 3. Cryptography & security model

All persisted data passes through the security barrier, which encrypts it
with **AES-256-GCM**, providing both confidentiality and integrity
(authenticated encryption) for every stored item, including configuration,
tokens, and secret values — the storage backend itself needs no trust.

The barrier's encryption key (the root/barrier key) is itself protected at
rest by being wrapped under a key derived from the unseal mechanism: either
reconstructed via Shamir's Secret Sharing threshold scheme from separately
held key shares, or unwrapped via a call to an external KMS/HSM in
auto-unseal mode. This means no single unseal-key holder, and no single
piece of storage, is sufficient to recover secrets on its own under the
Shamir model.

Client sessions are represented by **tokens**, each with an accrual of
policies, a TTL, and (for renewable tokens) a lease that must be periodically
renewed via the API or it expires. Vault issues **leases** for essentially
every dynamic secret and for tokens themselves; a lease encodes a maximum
TTL and revocation metadata, and Vault's expiration manager proactively
revokes leased secrets whose TTL has elapsed — e.g., dropping the database
user that was created for that lease. This lease/TTL model is what allows
Vault to keep the blast radius of any single leaked credential small: dynamic
secrets are unique per-consumer and self-expiring, unlike a static password
in a traditional vault entry.

The **transit** secrets engine implements encryption-as-a-service:
applications send plaintext (or hashes, for signing) to Vault's API and
receive ciphertext/signatures back, so the application process never has
direct access to the key material. Transit supports key rotation, versioned
keys, convergent encryption, and algorithms spanning AES-GCM, ChaCha20-Poly1305,
RSA, ECDSA, and Ed25519.

The **PKI** secrets engine turns Vault into an intermediate or root
certificate authority: it can generate CSRs, sign certificates against
configurable roles (constraining allowed domains, TTLs, key usages), and
issue short-lived leaf certificates on demand — an approach commonly used to
avoid distributing long-lived TLS private keys.

## 4. Protocols

Vault's primary and canonical interface is **HTTPS/REST with JSON payloads**;
essentially every operation — reading a secret, authenticating, managing
policy — is expressed as an HTTP request against a versioned API path, and
the official CLI and UI are themselves thin clients over this API.

Internally, Vault Enterprise's replication streams (Performance and Disaster
Recovery Replication) use **gRPC** between primary and secondary clusters for
efficient, low-latency propagation of encrypted data and WAL-like state.

For authentication, Vault does not invent new credential protocols; instead
each auth method plugin bridges an existing identity protocol into a Vault
token:

- **LDAP** — binds against a directory server using a supplied
  username/password.
- **OIDC/OAuth2** — delegates to an external identity provider, validating
  ID tokens and mapping claims to policies (also used for the browser-based
  SSO login flow in the Vault UI/CLI).
- **Kubernetes** — validates a pod's projected service account token
  against the Kubernetes TokenReview API.
- **Cloud IAM** (AWS, GCP, Azure) — verifies a signed cloud-native identity
  document or STS request against the respective cloud provider's API.
- **AppRole** — a Vault-specific machine-authentication protocol using a
  `role_id`/`secret_id` pair, intended for automated workloads (e.g. CI
  runners) that cannot present a cloud identity or Kubernetes token.

## 5. Threat model & known limitations

Vault is explicitly not a personal password manager. It has no consumer
UX — no browser autofill, no personal-item categories (credit cards, secure
notes), no cross-device end-user sync story, and no design intent around
individual usability. Its threat model assumes a security team operating
infrastructure on behalf of many non-human consumers, not an individual
protecting their own logins.

Running Vault safely is operationally heavy: it requires standing up and
maintaining an HA cluster, choosing and operating a storage backend,
managing TLS for the API listener, configuring audit devices, and building
processes around auth method and secrets engine lifecycle. This is a
meaningfully larger operational burden than installing a password manager
app.

The **unseal key custody problem** is a recurring operational and
governance challenge under the Shamir model: key shares must be distributed
to distinct trusted humans, stored securely and durably (a lost or
compromised threshold of shares means, respectively, an unrecoverable vault
or a vault an attacker can seal/unseal), and rotated periodically — auto-unseal
via cloud KMS avoids the human-custody problem but shifts trust onto the
cloud provider's KMS and its own IAM.

A compromised **root token** — Vault's initial, unrestricted superuser
credential — has essentially unbounded blast radius: full read/write over
every path, the ability to rewrite policy, and the ability to generate new
tokens with any privilege. Standard guidance is to generate a root token
only for bootstrapping or emergency use, then revoke it immediately in favor
of least-privilege tokens issued through auth methods.

Comprehensive **audit logging** (Vault's audit devices, which record every
request and response, including secrets read) is considered a near-mandatory
control given how much authority flows through the system, and organizations
should treat unaudited Vault deployments as a significant risk gap.

For a team or individual asking "what's a 1Password alternative," Vault is
almost never the right fit unless the actual requirement is machine-to-machine
dynamic secrets, PKI issuance, or encryption-as-a-service at infrastructure
scale — the operational overhead, lack of consumer UX, and infrastructure-first
threat model make it a poor substitute for personal or small-team password
management.

## 6. Sources/references

This chapter is based on HashiCorp's publicly available Vault documentation
(architecture, secrets engines, auth methods, seal/unseal, and replication
guides), HashiCorp's public statements regarding the August 2023 BUSL
relicensing, the Linux Foundation's public announcement of the OpenBao fork,
and the publicly available Vault open-source codebase and its documented
release history. No specific version numbers or CVE identifiers are cited
here; consult HashiCorp's official documentation site and changelog for
version-specific details before making deployment decisions.
