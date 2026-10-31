# Orin Enclave threat model

## Assets

| Asset | Why it matters |
| --- | --- |
| GitHub App private key (`orin-dx-pr-bot`) | Mints tokens for every repository the App is installed on, with every permission the App has, until rotated |
| App JWT | Valid for up to 10 minutes; can request installation tokens of any scope the App has |
| Installation tokens | One repo, `pull_requests: write` + `contents: read`, valid about 1 hour |
| The human's approval | The control everything else rests on |

## Adversaries

1. **An agent or tool running as the user** (the main one). It can run any program, read and write
   every file the user can, and watch process lists. It cannot type into the system authentication
   dialog or touch the sensor.
2. **Someone with a copy of the disk or a backup**, without this Mac's Secure Enclave.
3. **Network attackers** between the Mac and `api.github.com`.
4. Out of scope: root or kernel compromise, physical access to an unlocked Mac, compromise of GitHub.

## Mitigations

- **Key at rest.** The App key is AES-GCM encrypted under a key agreed with a P-256 key that lives
  in the Secure Enclave (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `privateKeyUsage` plus
  `userPresence` or `biometryCurrentSet`). The file is useless off this Mac. Format 2 authenticates
  the whole header (magic, policy, enclave key blob, ephemeral point) as AAD.
- **Approval per mint.** Every new token requires the Secure Enclave key, which requires Touch ID
  (or the password, under `userPresence`). The prompt names the repo, validated against
  `^[A-Za-z0-9._-]{1,100}$` so the prompt text cannot be steered. Reuse of a previous approval is
  disabled (`touchIDAuthenticationAllowableReuseDuration = 0`).
- **No signing oracle, no JWT at rest.** The helper builds the JWT itself with fixed claims
  (`iat` now-60, `exp` now+540, `iss` the App id) and only ever sends it to `api.github.com`. Earlier
  versions signed arbitrary stdin and cached the JWT on disk; both are gone.
- **Least privilege.** The token request names one repository and exactly `pull_requests: write`,
  `contents: read`. GitHub's reply is checked; a token with any other scope is revoked and not
  printed.
- **Transport.** URLSession over HTTPS to a fixed host, ephemeral session (no cookies, cache or
  credential store), redirects refused.
- **Files.** State and cache directories are 0700 and must be real directories owned by the user;
  files are created with `O_CREAT|O_EXCL|O_NOFOLLOW` and mode 0600, fsynced, then renamed into place,
  and are refused on read if group/other bits are set. Paths come from the user database, not
  `$HOME`; release builds accept no path overrides (only `-D OE_TEST_BUILD` builds do).
- **Replacing a key** requires a user-presence check before anything is overwritten.
- **Process integrity.** Hardened runtime (`codesign --options runtime`) blocks `DYLD_*` injection
  and unsigned code in the genuine helper. Installing into `/Applications` keeps a user-level agent
  from replacing the binary. `bin/pr-bot-token` pins `PATH` and ignores the environment.
- **Plaintext hygiene.** PEM input, DER key bytes and decrypted buffers are overwritten with
  `memset_s` after use (best effort).

## Residual risks

1. **Touch ID proves presence, not intent or caller.** A same-user agent can run the helper for a
   real repo and the prompt looks exactly like a legitimate one. Only approve prompts that match
   something you just asked for.
2. **Token cache window.** For 10 minutes after a mint, any same-user program can get that repo's
   token from the helper, or read the 0600 cache file, without a prompt. The alternative, a prompt
   for every `gh` call, trains people to approve blindly, which is worse. `orin-enclave forget`
   clears it.
3. **The Secure Enclave key blob is not bound to code identity under ad hoc signing.** CryptoKit's
   `dataRepresentation` blob can be used by any process of the same user on the same Mac. A
   malicious program can load the blob, show a prompt with its own wording under its own (possibly
   look-alike) app name, and on approval decrypt the App key itself. One mistaken approval then means
   the App key is compromised until rotated. Rotate the App key if you ever approve a prompt you did
   not expect.
4. **Password fallback** under `userPresence`: someone who knows the login password can approve.
   `--biometry-only` removes this, at the cost of invalidation when enrolled fingerprints change and
   no approvals without a sensor.
5. **Memory.** Wiping is best effort; copies inside Swift, Foundation and `SecKey` may survive until
   the process exits. The helper is short-lived.
6. **`contents: read`** means tokens cannot push. That is deliberate; widening it widens every
   residual risk above.

## What Developer ID signing and a keychain access group would add

Ad hoc signing gives the binary no stable identity the system can bind a key to. With a Developer ID
Application certificate:

- The enclave key can be created as a **persistent data-protection keychain item**
  (`kSecAttrTokenIDSecureEnclave`, `kSecAttrIsPermanent`, `kSecUseDataProtectionKeychain`) in a
  **keychain access group** `<TEAMID>.dev.orin-dx.enclave`. Only code signed by that team with the
  `keychain-access-groups` entitlement (embedded via a Developer ID provisioning profile) can use it.
  That closes residual risk 3: other programs can still run the genuine helper (risk 1), but cannot
  use the key with their own prompt text or extract the App key.
- Notarization and a secure timestamp let Gatekeeper verify the bundle and make tampering visible.
- This needs a re-seal (new keychain-bound enclave key); the current format would gain a reference to
  the keychain item instead of the blob.

### Getting a Developer ID Application certificate and notarizing

1. Enroll in the Apple Developer Program (individual or organization). Only the Account Holder can
   create Developer ID certificates.
2. Create the certificate: Xcode > Settings > Accounts > Manage Certificates > "+" > Developer ID
   Application; or on developer.apple.com under Certificates, upload a CSR made with Keychain Access
   > Certificate Assistant > Request a Certificate From a Certificate Authority.
3. Confirm it is in the login keychain: `security find-identity -v -p codesigning`.
4. Build: `SIGN_IDENTITY="Developer ID Application: <Name> (<TEAMID>)" ./build.sh` (hardened
   runtime and `--timestamp` are applied automatically).
5. Store notary credentials once (prompts for an app-specific password created at
   appleid.apple.com; nothing is written to the repo):
   `xcrun notarytool store-credentials orin-enclave-notary --apple-id <apple-id> --team-id <TEAMID>`
6. Submit and staple:
   ```sh
   ditto -c -k --keepParent "build/Orin Enclave.app" build/OrinEnclave.zip
   xcrun notarytool submit build/OrinEnclave.zip --keychain-profile orin-enclave-notary --wait
   xcrun stapler staple "build/Orin Enclave.app"
   spctl --assess -vv "build/Orin Enclave.app"
   ```
7. For the keychain access group, also create a Developer ID provisioning profile for the App ID
   `dev.orin-dx.enclave` with the keychain sharing capability, embed it as
   `Contents/embedded.provisionprofile`, and sign with an entitlements file listing
   `<TEAMID>.dev.orin-dx.enclave` under `keychain-access-groups`.
