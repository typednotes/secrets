# OpenBao

## 1. Overview

**OpenBao** is a Linux Foundation-hosted fork of HashiCorp Vault,
created in 2023 in direct response to HashiCorp's relicensing of Vault
(and its other open-source projects) from the OSI-approved Mozilla
Public License 2.0 (MPL-2.0) to the source-available, non-OSI Business
Source License (BUSL 1.1) — see the licensing discussion in
[`hashicorp-vault.md`](hashicorp-vault.md#1-overview). OpenBao
continues development of the pre-relicensing Vault codebase under
MPL-2.0, and is governed as a genuine open-source project under Linux
Foundation stewardship rather than a single vendor — multiple
companies (including IBM/Red Hat, and cloud providers packaging it as
a managed offering) contribute and govern it, rather than one company
holding unilateral relicensing power.

Like Vault, OpenBao occupies the "infrastructure secrets management"
niche discussed in [`hashicorp-vault.md`](hashicorp-vault.md) rather
than the consumer password-manager niche — it is not a 1Password/
Bitwarden-style personal vault, and the same caveats about lacking
consumer UX apply equally here. It's included in this survey because,
for teams whose actual requirement *is* machine-to-machine dynamic
secrets, PKI, or encryption-as-a-service (the use cases Vault serves),
license posture is often the deciding factor between the two, making
OpenBao the natural point of comparison.

## 2. Architecture

OpenBao's architecture is, by design, nearly identical to Vault's at
the fork point: the same **security barrier** encrypting all data
before it touches storage, the same pluggable **storage backend**
model (Raft integrated storage as the default, plus Consul and others),
the same **seal/unseal** lifecycle, and the same **secrets engine** /
**auth method** plugin systems described in
[`hashicorp-vault.md`](hashicorp-vault.md#2-architecture). Since the
fork, the two projects have begun to diverge incrementally as each
accepts different community contributions and prioritizes different
roadmap items, but the core request path, plugin architecture, and
policy model remain structurally the same, and OpenBao maintains
strong **API compatibility** with Vault — most existing Vault
clients, CLI usage patterns, and Terraform providers work against an
OpenBao server with little to no change, which was an explicit design
goal to ease migration for organizations leaving Vault over the
licensing change.

Notable areas where OpenBao has continued independent development
post-fork include community-driven auth method and secrets engine
additions, and features aimed at addressing gaps some users had
already raised against upstream Vault before the fork (e.g. enhancements
to namespace-like tenant isolation without requiring an Enterprise
license, since OpenBao has no separate paid "Enterprise" tier
gatekeeping features the way HashiCorp's commercial product line
does).

## 3. Cryptography & security model

The cryptographic design is inherited directly from Vault and remains
essentially the same: **AES-256-GCM** authenticated encryption at the
security barrier for all persisted data, a root/barrier key protected
either via **Shamir's Secret Sharing** (`t`-of-`n` threshold
reconstruction) or **auto-unseal** through an external KMS/HSM, and the
same token/lease/TTL model for bounding the blast radius of any single
credential — see
[`hashicorp-vault.md`](hashicorp-vault.md#3-cryptography--security-model)
for the full mechanics, which apply here without meaningful
divergence. The `transit` (encryption-as-a-service) and `pki`
(certificate authority) secrets engines are likewise present with
equivalent semantics.

Because OpenBao and Vault share this security architecture and, at the
time of the fork, an essentially identical codebase, any structural
cryptographic strengths or weaknesses discussed for Vault apply
equally to OpenBao pre-divergence. Ongoing security patches are no
longer automatically shared between the two projects post-fork,
however — each now runs its own release and disclosure process, so a
fix merged upstream in one project does not automatically appear in
the other without a maintainer independently porting it. Organizations
running either should track that project's own advisories rather than
assuming parity going forward.

## 4. Protocols

OpenBao's protocol surface mirrors Vault's: **HTTPS/REST with JSON
payloads** as the canonical API, the same auth-method-mediated bridges
into external identity protocols (LDAP, OIDC/OAuth2, Kubernetes
service account tokens, cloud IAM, AppRole), and gRPC for internal
replication where equivalent replication functionality is implemented.
Because compatibility with existing Vault tooling was an explicit
goal, most Vault API clients and SDKs work against OpenBao by pointing
them at a different server address — see
[`hashicorp-vault.md`](hashicorp-vault.md#4-protocols) for the
protocol details, which transfer directly.

## 5. Threat model & known limitations

All of the operational caveats that apply to Vault apply equally to
OpenBao: it is not a personal password manager, it carries meaningful
operational overhead to run safely (HA cluster, storage backend
choice, TLS termination, audit logging), the **unseal key custody
problem** under Shamir's Secret Sharing is unchanged, and a compromised
root token carries the same essentially unbounded blast radius — see
[`hashicorp-vault.md`](hashicorp-vault.md#5-threat-model--known-limitations)
for the full discussion.

Specific to OpenBao as a *fork*, two additional considerations matter:

- **Smaller/younger security-review history.** OpenBao inherited
  Vault's codebase and its review history up to the fork point, but
  its own independent audit trail, CVE disclosure history, and
  production track record as a distinct project are shorter than
  Vault's much longer, single-vendor-maintained history — a
  consideration similar in kind to the reimplementation-risk discussion
  in [`vaultwarden.md`](vaultwarden.md#5-threat-model--known-limitations),
  though OpenBao differs from Vaultwarden in an important way: it
  forked an existing, mature open-source codebase wholesale rather than
  reimplementing a protocol from scratch, so it inherits Vault's
  pre-fork maturity directly rather than starting from zero.
- **Governance and long-term divergence risk.** Linux Foundation
  multi-stakeholder governance reduces the single-vendor relicensing
  risk that caused the fork in the first place, but it also means
  feature/security parity with upstream Vault is no longer guaranteed
  by a shared codebase — organizations should evaluate OpenBao on its
  own roadmap and disclosure practices going forward, not simply as
  "Vault, but free."

For the same reasons Vault is rarely the right pick for an individual
or small team's "1Password alternative" search (see
[`hashicorp-vault.md`](hashicorp-vault.md#5-threat-model--known-limitations)),
OpenBao is equally unsuited to that use case — it should be compared
against Vault specifically, not against consumer password managers,
and the deciding factor between the two is almost always licensing
posture and governance preference rather than a functional or
cryptographic difference.

## 6. Sources/references

This chapter is based on the Linux Foundation's public announcement
and governance documentation for the OpenBao project, OpenBao's
publicly available open-source codebase and documentation, and
HashiCorp's public statements regarding the August 2023 BUSL
relicensing that prompted the fork (also referenced in
[`hashicorp-vault.md`](hashicorp-vault.md#6-sourcesreferences)). No
specific version numbers or CVE identifiers are cited here; consult
OpenBao's official documentation site and security advisories for
version-specific and current disclosure details before making
deployment decisions.
