# Key Derivation Functions

A key derivation function (KDF) turns a low-entropy secret — typically
a human-chosen master password — into a fixed-length cryptographic key
suitable for encryption or authentication. Every password manager in
[`docs/alternatives.md`](alternatives.md) uses one of the three KDFs
below at the base of its key hierarchy (see e.g.
[`tools/bitwarden.md`](tools/bitwarden.md) and
[`tools/keepassxc.md`](tools/keepassxc.md) for how each plugs it in).

## Why not just hash the password?

A plain hash (SHA-256, etc.) is fast — attackers can compute billions
per second on commodity GPUs, so brute-forcing a dictionary or
mask-based guess against a stolen hash is cheap. A KDF is built to be
*deliberately expensive* to compute, so that deriving the correct key
still takes a fraction of a second for a legitimate user (one attempt)
but becomes prohibitively expensive for an attacker (billions of
attempts). All three KDFs below share this "deliberately slow,
tunable cost" design; they differ mainly in *which* resource they make
expensive.

```
password ──► KDF(password, salt, cost params) ──► derived key (fixed length)
```

The **salt** is a random value stored alongside the derived data. It
does not need to be secret — its job is to make precomputed rainbow
tables useless and to ensure two users with the same password get
different derived keys.

## PBKDF2

**Password-Based Key Derivation Function 2** (RFC 2898 / RFC 8018) is
the oldest and simplest of the three, standardized in 2000.

- **Mechanism:** repeatedly apply an HMAC (usually HMAC-SHA256) to the
  password and salt, chaining the output back into itself for a
  configurable **iteration count** (e.g. 100,000–600,000+).
- **Cost dimension:** compute time only. It uses negligible memory
  (a few hundred bytes), which is exactly its weakness.
- **Weakness:** because it is memory-light, it parallelizes extremely
  well on GPUs and ASICs/FPGAs. An attacker can run millions of
  candidate passwords per second per device by throwing more hardware
  at the problem, making PBKDF2 the least brute-force-resistant of the
  three per unit of legitimate-user latency.
- **Why it's still used:** it's simple, has no memory-hardness to
  misconfigure, is available in virtually every crypto library
  (including constrained/embedded and FIPS-certified environments),
  and remains acceptable when the iteration count is set high enough.
  LastPass and (as a legacy option) Bitwarden use PBKDF2-HMAC-SHA256.
- **Tuning knob:** iteration count. Higher is safer but slower for the
  legitimate user; this is the *only* lever, which is why a
  provider's default iteration count matters so much (see the
  LastPass incident discussion in [`tools/lastpass.md`](tools/lastpass.md)
  for what happens when it's set too low).

## scrypt

Designed by Colin Percival in 2009, specifically to close PBKDF2's
GPU/ASIC-parallelization gap.

- **Mechanism:** in addition to iterated hashing, scrypt allocates and
  repeatedly reads/writes a large pseudorandom array in memory
  (governed by parameter `N`, the number of elements, `r`, block
  size, and `p`, parallelization). Computing it correctly *requires*
  holding that whole array in memory at once.
- **Cost dimension:** both compute time and memory, making it
  **memory-hard**: an attacker cannot trade memory for extra parallel
  compute units without paying a steep time penalty (a
  time-memory trade-off attack becomes much more expensive than for
  PBKDF2).
- **Weakness:** memory-hardness alone doesn't defeat all custom
  hardware — a sufficiently well-funded attacker can still build ASICs
  with fast, large on-chip memory (this is part of why scrypt saw
  large-scale ASIC investment once cryptocurrencies adopted it).
  It's also a single memory-access-pattern design, which turned out to
  be easier to attack with clever hardware than Argon2's design.
- **Notable adoption:** originally for Tarsnop/BSD systems, and
  widely known from Litecoin's proof-of-work. Less common in modern
  password managers than PBKDF2 or Argon2, but still used in some
  disk-encryption and legacy systems.
- **Tuning knobs:** `N` (memory/CPU cost, must be a power of two),
  `r` (block size, affects memory bandwidth), `p` (parallelization).

## Argon2

Winner of the 2015 Password Hashing Competition, and the current
best-practice recommendation (OWASP, IETF RFC 9106) for new designs.

- **Mechanism:** fills a memory array with pseudorandom blocks derived
  from the password and salt, then makes multiple passes over that
  array, mixing blocks together in a pattern that depends on the
  chosen variant. Three variants exist:
  - **Argon2d** — data-dependent memory access (fastest, most
    resistant to GPU cracking, but the access pattern depends on the
    password, which opens a theoretical side-channel/cache-timing
    risk — fine for password hashing where you control the machine,
    riskier if an attacker can observe cache behavior).
  - **Argon2i** — data-*independent* memory access (immune to that
    side-channel, but slightly weaker against pure GPU brute force for
    the same cost).
  - **Argon2id** (recommended default, used by Bitwarden, KeePassXC,
    and most modern tools) — a hybrid: data-independent for the first
    pass, data-dependent afterward, combining side-channel resistance
    with strong GPU/ASIC resistance.
- **Cost dimension:** memory, compute time, *and* parallelism — all
  three are independently tunable, which is Argon2's key advantage
  over scrypt's more rigid `N`/`r`/`p` coupling.
- **Tuning knobs:**
  - `m` (memory cost, in KiB) — the dominant cost driver; large memory
    requirements make custom ASICs far more expensive to build than
    for PBKDF2/scrypt.
  - `t` (time cost / number of passes over memory).
  - `p` (parallelism / number of lanes) — lets the algorithm use
    multiple CPU cores without weakening memory-hardness the way naive
    parallel PBKDF2 would.
- **Why it's the current recommendation:** it offers the best
  understood resistance to GPU, FPGA, and ASIC cracking per unit of
  legitimate-user latency, has three independent cost knobs instead of
  one or two, and had the benefit of a public competition and years of
  cryptanalysis before wide adoption. KeePassXC defaults to Argon2id;
  Bitwarden, Dashlane, and Proton-ecosystem tools have moved to
  Argon2-family KDFs as well (see the respective chapters under
  [`tools/`](tools/)).

## Comparison

| | PBKDF2 | scrypt | Argon2 (id) |
|---|---|---|---|
| Standardized | RFC 2898 (2000) | 2009, RFC 7914 | RFC 9106 (2015 PHC winner) |
| Memory-hard | No | Yes | Yes |
| Independent cost knobs | 1 (iterations) | 2 (`N`, coupled with `r`/`p`) | 3 (memory, time, parallelism) |
| GPU/ASIC resistance | Weak | Good | Best understood today |
| Side-channel considerations | N/A | Some | Argon2id mitigates via hybrid access pattern |
| Typical use today | Legacy / FIPS-constrained systems | Disk encryption, some legacy vaults | New designs, current best practice |

## Practical takeaway

The security of a "master password protects everything" system rests
almost entirely on the KDF's cost parameters, since the master
password itself is the only secret an attacker who steals the
encrypted vault needs to guess. Prefer Argon2id where available, size
its memory parameter as high as the deployment target (server load,
mobile battery/RAM, browser extension limits) can tolerate, and treat
low default iteration/memory settings as a real, exploitable
weakness — not a cosmetic configuration detail.
