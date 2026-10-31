<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/orin-enclave-dark.svg">
  <img src="docs/images/orin-enclave-light.svg" alt="Orin Enclave" width="96">
</picture>

# Orin Enclave

Orin Enclave is a small macOS helper that lets coding agents open pull requests as the
`orin-dx-pr-bot` GitHub App, so a human can review and approve them, without the agent ever holding
the App's private key.

The App private key is sealed to this Mac's Secure Enclave. When an agent needs a token, the helper
shows a Touch ID prompt that names the repository ("Orin Enclave is trying to mint a GitHub token for
orin-dx/&lt;repo&gt;"), unseals the key in memory, builds the App JWT, exchanges it with GitHub for an
installation token limited to **that one repository** and to **`pull_requests: write` and
`contents: read` only**, and prints that token. The JWT never leaves the process; no command signs
data chosen by the caller.

## Pieces

| Path | Role |
| --- | --- |
| `Sources/main.swift` | `orin-enclave`, the helper (`token`, `seal`, `migrate`, `forget`, `status`) |
| `Resources/` | bundle identity (`Orin Enclave`, `dev.orin-dx.enclave`) and icon |
| `build.sh` | builds `build/Orin Enclave.app`, hardened runtime, ad hoc or Developer ID signed |
| `bin/pr-bot-token` | thin wrapper: validates the repo name and runs `orin-enclave token <repo>` |
| `bin/gh-shim`, `bin/pr-bot-guard.sh`, `adapters/` | the `gh` shim and agent guard hooks; the shim calls `pr-bot-token` to get a token for the repo it is acting on, the guard keeps agents from reaching the key or helper state directly |

## Threat model in brief

Full version: [docs/threat-model.md](docs/threat-model.md).

- **Protects against:** the private key being copied off disk or out of a backup (the sealed file is
  useless without this Mac's Secure Enclave); an agent silently minting tokens (each new token needs
  Touch ID); tokens broader than needed (one repo, two permissions, checked again on GitHub's reply
  and revoked if wider); JWT reuse (it is never stored).
- **Honest limits:**
  - Touch ID proves that *a person approved*, not *which program asked*. Any program running as your
    user can run the helper and trigger a prompt with a real repo name in it. Approve only prompts
    you expect.
  - After a token is minted it is reused without a prompt for up to 10 minutes for that repo. During
    that window any program running as your user can get it from the helper (or read it from the
    0600 cache file). `orin-enclave forget` clears the cache.
  - With an ad hoc signature, the Secure Enclave key blob is not bound to this app's code signature.
    A program running as your user that you approve once could unseal the App key itself. Developer
    ID signing plus a keychain access group closes this; see the threat model.
  - A prompt that falls back to your login password is weaker than Touch ID alone; see
    `seal --biometry-only`.

## Build and install

Requires macOS 14+, Apple silicon or a T2 Mac, and the Xcode command line tools.

```sh
./build.sh                                   # ad hoc signed, hardened runtime
# or: SIGN_IDENTITY="Developer ID Application: <Name> (<TEAMID>)" ./build.sh
sudo cp -R "build/Orin Enclave.app" /Applications/   # admin-owned: your user cannot swap the binary
#   (without admin: mkdir -p ~/Applications && cp -R "build/Orin Enclave.app" ~/Applications/)
install -m 700 bin/pr-bot-token ~/.config/orin-dx/pr-bot-token
```

Below, `orin-enclave` means `"/Applications/Orin Enclave.app/Contents/MacOS/orin-enclave"` (or the
`~/Applications` copy). It must run from inside the bundle so the prompt says "Orin Enclave".

First-time setup (download a private key from the App's settings page, then delete the file):

```sh
orin-enclave seal < orin-dx-pr-bot.private-key.pem          # Touch ID or password
orin-enclave seal --biometry-only < orin-dx-pr-bot.private-key.pem   # Touch ID only (see below)
```

Check it: `~/.config/orin-dx/pr-bot-token <repo> >/dev/null && echo ok` (one prompt naming the repo).

Tokens can open, update and comment on pull requests and read code. They cannot push: push branches
with your own credentials, or change `requestedPermissions` in `Sources/main.swift` deliberately.

## Migrating from "Orin DX PR Bot"

The rename moves state from `~/Library/Application Support/OrinDX-PR-Bot/` to
`~/Library/Application Support/Orin Enclave/` and the bundle id from `dev.orin-dx.pr-bot` to
`dev.orin-dx.enclave`. You do **not** need the PEM again:

```sh
"/Applications/Orin Enclave.app/Contents/MacOS/orin-enclave" migrate   # one Touch ID prompt
```

`migrate` unseals the existing key with the existing Secure Enclave key (the bundle id is not part of
that key, so the new bundle can use it), re-wraps it in format 2 (header authenticated), writes the
new file with mode 0600, verifies it decrypts, and only then deletes the old two files, the old
directory, and the old cache directory (which held an App JWT and tokens). If anything fails, nothing
is removed and the old app keeps working. Afterwards remove the old app:
`rm -rf ~/Applications/"Orin DX PR Bot.app"`.

A migrated key keeps the approval policy it was created with (Touch ID or password). To switch to
Touch ID only you need the PEM (`seal --replace --biometry-only`), or generate a new key in the App
settings, seal it, and delete the old key there.

## Rotate the key

Generate a new key in the App settings, `orin-enclave seal --replace < new.pem` (asks for approval
before anything is replaced), check a token mints, then delete the old key in the App settings.

## Touch ID only, or Touch ID or password?

`seal` defaults to `userPresence`: Touch ID, falling back to the login password. `--biometry-only`
uses `biometryCurrentSet`: Touch ID only, with the fingerprints enrolled at seal time. It shuts out
anyone who knows or watches you type your password, and enrolling a new finger cannot be used to
approve. The costs: no prompt can be approved with the lid closed and no Touch ID keyboard, and any
change to enrolled fingerprints permanently invalidates the sealed key, so you must re-seal from the
PEM or rotate the App key.

## State

- `~/Library/Application Support/Orin Enclave/key.sealed`: the Secure Enclave key blob and the
  encrypted App key (directory 0700, file 0600).
- `~/Library/Caches/Orin Enclave/token-<repo>.json`: tokens reused for up to 10 minutes (0700/0600).
- Nothing else. No environment variable changes these paths in a release build; `TEST_BUILD=1
  ./build.sh` produces a separate `orin-enclave-test` that keeps state under `$OE_TEST_STATE_DIR`.

## License

MIT. See [LICENSE](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
