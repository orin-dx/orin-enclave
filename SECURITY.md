# Security policy

## Reporting

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (private security
advisory) on this repository. Do not open a public issue. Include the macOS version, how the app was
built and signed, and steps to reproduce. Never include private keys, tokens, or sealed key files in
a report; describe them instead. Expect an acknowledgement within a week.

## Scope

In scope:

- `Sources/main.swift` (the `orin-enclave` helper): anything that lets a caller obtain the App
  private key, an App JWT, a token for a repository other than the one approved, a token with
  permissions beyond `pull_requests: write` and `contents: read`, or a token without an approval
  prompt outside the documented 10-minute per-repo cache.
- Sealed file format and file handling: wrong modes, symlink or race issues, unauthenticated header
  fields, failure to wipe where wiping is claimed.
- `build.sh` signing (hardened runtime, identity, timestamp) and `bin/pr-bot-token`.

Out of scope (known and documented; see [docs/threat-model.md](docs/threat-model.md)):

- A program running as the same user triggering a genuine prompt, or reading a cached token during
  the cache window.
- With ad hoc signing: a same-user program using the Secure Enclave key blob directly after a human
  approves its prompt.
- Root, kernel, or physical attacks on an unlocked Mac; compromise of GitHub or of the App's
  settings page.
- The `gh` shim and guard hooks are maintained alongside but reviewed separately.

## Known limits

- Touch ID proves a person approved, not which program asked.
- Plaintext key bytes are wiped on a best-effort basis; Swift, Foundation and Security framework
  copies cannot all be reached.
- `userPresence` keys accept the login password as a fallback; `--biometry-only` removes it at the
  cost of invalidation when fingerprints change.
