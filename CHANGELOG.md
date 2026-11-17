# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 1.3.1 are described in their git tags (`git tag -n` and `git show vX.Y.Z`) and
commit messages.

## [Unreleased]

## [1.3.1] — 2026-11-17

### Added

- A bicolor sideways-T logo (`logo.svg`).

### Changed

- Crates and Docker images are published from a version tag only after the main-branch CI run for
  that exact commit has succeeded; publication waits for it rather than racing it.
- Dependencies updated to their latest semver-compatible versions, and GitHub Actions to their
  current major versions (Node 24). argon2 0.6, toml 1 and testcontainers 0.28 are not yet taken.
- CI now also checks formatting (`cargo fmt --all --check`); the workspace is formatted. Clippy
  warnings already failed CI.
