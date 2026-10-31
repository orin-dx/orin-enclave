import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

// orin-enclave: the "Orin Enclave" helper. It holds the orin-dx-pr-bot GitHub App private key sealed to
// this Mac's Secure Enclave and, after Touch ID, mints a GitHub installation token scoped to ONE repo with
// ONLY pull_requests:write and contents:read. The App JWT is built, used and discarded in memory; nothing
// that signs caller-chosen data is exposed.
//
//   token <repo>                         print a scoped installation token (Touch ID unless cached)
//   seal [--replace] [--biometry-only]   read a PKCS#1 PEM on stdin and seal it (Touch ID)
//   migrate                              move pre-rename state into the Orin Enclave layout (Touch ID)
//   forget [<repo>]                      delete cached tokens (no prompt)
//   status                               report whether a key is sealed (no prompt, no keychain access)

// MARK: - Fixed identity (not configurable at run time)

let toolName = "orin-enclave"
let toolVersion = "2.0.0"
let githubAppID = 5512928  // public App id of orin-dx-pr-bot; not a secret
let githubOrg = "orin-dx"
let apiHost = "api.github.com"
let requestedPermissions: [String: String] = ["pull_requests": "write", "contents": "read"]
/// A cached token is handed out without a prompt for at most this long after it was minted.
let cacheLifetime: TimeInterval = 600
/// Never hand out a cached token with less than this much life left on GitHub's side.
let minRemainingLifetime: TimeInterval = 300

struct EnclaveError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

func fail(_ message: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("\(toolName): \(message)\n".utf8))
    exit(code)
}

func note(_ message: String) {
    FileHandle.standardError.write(Data("\(toolName): \(message)\n".utf8))
}

// MARK: - Paths

struct Paths {
    let stateDir: String
    let cacheDir: String
    let legacyStateDir: String
    let legacyCacheDir: String

    var sealedFile: String { stateDir + "/key.sealed" }
    var legacyBlob: String { legacyStateDir + "/se-key.blob" }
    var legacySealed: String { legacyStateDir + "/sealed-key.bin" }
    func cacheFile(_ repo: String) -> String { cacheDir + "/token-\(repo.lowercased()).json" }
}

/// The home directory from the user database, not from $HOME, so the environment cannot redirect state.
func userHome() -> String {
    guard let entry = getpwuid(getuid()), let dir = entry.pointee.pw_dir else {
        fail("cannot determine your home directory")
    }
    return String(cString: dir)
}

func resolvePaths() -> Paths {
    #if OE_TEST_BUILD
        // Test builds only (swiftc -D OE_TEST_BUILD): all state lives under a caller-chosen directory.
        guard let root = ProcessInfo.processInfo.environment["OE_TEST_STATE_DIR"], root.hasPrefix("/") else {
            fail("test build: set OE_TEST_STATE_DIR to an absolute directory")
        }
        note("TEST BUILD: state under \(root)")
        return Paths(
            stateDir: root + "/state", cacheDir: root + "/cache",
            legacyStateDir: root + "/legacy-state", legacyCacheDir: root + "/legacy-cache")
    #else
        let home = userHome()
        return Paths(
            stateDir: home + "/Library/Application Support/Orin Enclave",
            cacheDir: home + "/Library/Caches/Orin Enclave",
            legacyStateDir: home + "/Library/Application Support/OrinDX-PR-Bot",
            legacyCacheDir: home + "/Library/Caches/OrinDX-PR-Bot")
    #endif
}

// MARK: - Private file I/O

func posixError(_ what: String) -> EnclaveError {
    EnclaveError("\(what): \(String(cString: strerror(errno)))")
}

func exists(_ path: String) -> Bool {
    var st = stat()
    return lstat(path, &st) == 0
}

/// The directory must be a real directory (not a symlink), owned by us, with no group/other access.
func checkPrivateDir(_ path: String) throws {
    var st = stat()
    guard lstat(path, &st) == 0 else { throw posixError("cannot inspect \(path)") }
    guard st.st_mode & S_IFMT == S_IFDIR else {
        throw EnclaveError("\(path) is not a directory (symlinks are refused)")
    }
    guard st.st_uid == getuid() else { throw EnclaveError("\(path) is not owned by you") }
    guard st.st_mode & 0o077 == 0 else {
        throw EnclaveError("\(path) is accessible to other users; run: chmod 700 \"\(path)\"")
    }
}

func ensurePrivateDir(_ path: String) throws {
    if mkdir(path, 0o700) != 0 && errno != EEXIST { throw posixError("cannot create \(path)") }
    try checkPrivateDir(path)
}

/// Reads a regular file we own with no group/other access. Returns nil if it does not exist.
func readPrivate(_ path: String, limit: Int = 1 << 20) throws -> Data? {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 {
        if errno == ENOENT { return nil }
        throw posixError("cannot open \(path)")
    }
    defer { close(fd) }
    var st = stat()
    guard fstat(fd, &st) == 0 else { throw posixError("cannot inspect \(path)") }
    guard st.st_mode & S_IFMT == S_IFREG, st.st_uid == getuid() else {
        throw EnclaveError("\(path) is not a regular file you own")
    }
    guard st.st_mode & 0o077 == 0 else {
        throw EnclaveError("\(path) is accessible to other users; run: chmod 600 \"\(path)\"")
    }
    guard st.st_size <= limit else { throw EnclaveError("\(path) is unexpectedly large") }
    var data = Data(count: Int(st.st_size))
    var filled = 0
    let ok: Bool = data.withUnsafeMutableBytes { buffer in
        guard let base = buffer.baseAddress else { return true }
        while filled < buffer.count {
            let n = read(fd, base + filled, buffer.count - filled)
            if n < 0 {
                if errno == EINTR { continue }
                return false
            }
            if n == 0 { break }
            filled += n
        }
        return true
    }
    guard ok else { throw posixError("cannot read \(path)") }
    data.count = filled
    return data
}

/// Writes atomically: a temp file is created with O_CREAT|O_EXCL and mode 0600 (never wider, even
/// briefly), filled, fsynced, then renamed over the target.
func writePrivate(_ data: Data, to path: String) throws {
    let dir = (path as NSString).deletingLastPathComponent
    let temp = dir + "/.tmp-\(getpid())-\(String(UInt64.random(in: 0...UInt64.max), radix: 16))"
    let fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw posixError("cannot create a file in \(dir)") }
    var written = 0
    let ok: Bool = data.withUnsafeBytes { buffer in
        guard let base = buffer.baseAddress else { return true }
        while written < buffer.count {
            let n = write(fd, base + written, buffer.count - written)
            if n < 0 {
                if errno == EINTR { continue }
                return false
            }
            written += n
        }
        return true
    }
    let synced = ok && fsync(fd) == 0
    close(fd)
    guard synced, rename(temp, path) == 0 else {
        let error = posixError("cannot write \(path)")
        unlink(temp)
        throw error
    }
}

// MARK: - Best-effort wiping of secrets

/// Overwrites the bytes we own. Best effort only: Swift, Foundation and Security may hold copies
/// (copy-on-write buffers, SecKey internals) that this cannot reach.
func wipe(_ data: inout Data) {
    data.withUnsafeMutableBytes { buffer in
        if let base = buffer.baseAddress, buffer.count > 0 { _ = memset_s(base, buffer.count, 0, buffer.count) }
    }
}

func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { buffer in
        if let base = buffer.baseAddress, buffer.count > 0 { _ = memset_s(base, buffer.count, 0, buffer.count) }
    }
}

// MARK: - Key handling

/// Extracts the DER body of a PKCS#1 "RSA PRIVATE KEY" PEM, working on bytes so no String copies are made.
func derFromPEM(_ input: Data) -> Data? {
    let begin = Array("-----BEGIN RSA PRIVATE KEY-----".utf8)
    let end = Array("-----END RSA PRIVATE KEY-----".utf8)
    var body: [UInt8] = []
    body.reserveCapacity(input.count)
    var line: [UInt8] = []
    line.reserveCapacity(128)
    var state = 0  // 0 before BEGIN, 1 in body, 2 after END
    func finishLine() {
        while line.last == 0x0D || line.last == 0x20 { line.removeLast() }
        if state == 0 && line == begin {
            state = 1
        } else if state == 1 && line == end {
            state = 2
        } else if state == 1 {
            body.append(contentsOf: line)
        }
        wipe(&line)
        line.removeAll(keepingCapacity: true)
    }
    for byte in input {
        if byte == 0x0A { finishLine() } else { line.append(byte) }
    }
    finishLine()
    defer { wipe(&body) }
    guard state == 2 else { return nil }
    var encoded = Data(body)
    defer { wipe(&encoded) }
    return Data(base64Encoded: encoded)
}

func rsaPrivateKey(_ der: Data) -> SecKey? {
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
    ]
    var error: Unmanaged<CFError>?
    return SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error)
}

enum ApprovalPolicy: UInt8 {
    /// Touch ID, or the login password when Touch ID is unavailable or fails.
    case userPresence = 1
    /// Touch ID only, with the fingerprints enrolled at seal time; enrolling or removing a finger
    /// permanently invalidates the key (re-seal from the PEM, or rotate the App key).
    case biometryCurrentSet = 2

    var flags: SecAccessControlCreateFlags {
        switch self {
        case .userPresence: return [.privateKeyUsage, .userPresence]
        case .biometryCurrentSet: return [.privateKeyUsage, .biometryCurrentSet]
        }
    }

    var label: String {
        switch self {
        case .userPresence: return "Touch ID or login password"
        case .biometryCurrentSet: return "Touch ID only, current fingerprints"
        }
    }
}

/// On-disk format 2, one file so it is replaced atomically:
///   "OPB2" | policy (1) | blob length (2, big endian) | Secure Enclave key blob | ephemeral P-256 point (65)
///   | AES-GCM nonce+ciphertext+tag of the PKCS#1 DER.
/// Everything before the AES-GCM box is the header and is authenticated as AAD.
struct SealedKeyFile {
    static let magic = Data("OPB2".utf8)
    static let kdfInfo = Data("orin-enclave sealed-key v2".utf8)
    static let pointLength = 65

    let policy: ApprovalPolicy
    let blob: Data
    let ephemeralPublic: Data
    var box = Data()

    var header: Data {
        var h = SealedKeyFile.magic
        h.append(policy.rawValue)
        h.append(UInt8(blob.count >> 8))
        h.append(UInt8(blob.count & 0xFF))
        h.append(blob)
        h.append(ephemeralPublic)
        return h
    }

    var encoded: Data { header + box }

    static func parse(_ data: Data) throws -> SealedKeyFile {
        let b = [UInt8](data)
        guard b.count > 7, Data(b[0..<4]) == magic else {
            throw EnclaveError("sealed key file is not in format 2")
        }
        guard let policy = ApprovalPolicy(rawValue: b[4]) else {
            throw EnclaveError("sealed key file names an unknown approval policy")
        }
        let blobLength = Int(b[5]) << 8 | Int(b[6])
        let blobEnd = 7 + blobLength
        let pointEnd = blobEnd + pointLength
        guard blobLength > 0, b.count > pointEnd + 28 else { throw EnclaveError("sealed key file is truncated") }
        return SealedKeyFile(
            policy: policy, blob: Data(b[7..<blobEnd]), ephemeralPublic: Data(b[blobEnd..<pointEnd]),
            box: Data(b[pointEnd...]))
    }
}

func derivedKey(_ secret: SharedSecret, salt: Data, info: Data) -> SymmetricKey {
    secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
}

/// Encrypts to the Secure Enclave key's public half. Needs no prompt: only the private half is gated.
func wrap(
    _ der: Data, to enclavePublic: P256.KeyAgreement.PublicKey, blob: Data, policy: ApprovalPolicy
) throws -> (SealedKeyFile, SymmetricKey) {
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let ephemeralPublic = ephemeral.publicKey.x963Representation
    let secret = try ephemeral.sharedSecretFromKeyAgreement(with: enclavePublic)
    let key = derivedKey(secret, salt: ephemeralPublic, info: SealedKeyFile.kdfInfo)
    var file = SealedKeyFile(policy: policy, blob: blob, ephemeralPublic: ephemeralPublic)
    guard let combined = try AES.GCM.seal(der, using: key, authenticating: file.header).combined else {
        throw EnclaveError("could not seal the key")
    }
    file.box = combined
    return (file, key)
}

/// Confirms a freshly written file decrypts, using the symmetric key already in hand (no prompt).
func verifyWritten(_ path: String, key: SymmetricKey) throws {
    guard let data = try readPrivate(path) else { throw EnclaveError("\(path) vanished after writing") }
    let file = try SealedKeyFile.parse(data)
    var der = try AES.GCM.open(AES.GCM.SealedBox(combined: file.box), using: key, authenticating: file.header)
    defer { wipe(&der) }
    guard rsaPrivateKey(der) != nil else { throw EnclaveError("verification of \(path) failed") }
}

func authenticationContext(_ reason: String) -> LAContext {
    let context = LAContext()
    context.localizedReason = reason
    context.touchIDAuthenticationAllowableReuseDuration = 0
    return context
}

/// Decrypts the sealed key. The Secure Enclave shows the approval prompt ("Orin Enclave is trying to
/// <reason>.") when the key agreement runs.
func unseal(_ file: SealedKeyFile, reason: String) throws -> Data {
    let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: file.blob, authenticationContext: authenticationContext(reason))
    let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: file.ephemeralPublic)
    let secret = try enclaveKey.sharedSecretFromKeyAgreement(with: ephemeral)
    let key = derivedKey(secret, salt: file.ephemeralPublic, info: SealedKeyFile.kdfInfo)
    return try AES.GCM.open(AES.GCM.SealedBox(combined: file.box), using: key, authenticating: file.header)
}

/// Reads the pre-rename format ("OPB1", two files, header not authenticated). Used only by `migrate`.
func unsealLegacy(blob: Data, sealed: Data, reason: String) throws -> (Data, P256.KeyAgreement.PublicKey) {
    let magic = Data("OPB1".utf8)
    let point = SealedKeyFile.pointLength
    guard sealed.count > magic.count + point + 28, sealed.prefix(magic.count) == magic else {
        throw EnclaveError("legacy sealed key file is not in the expected format")
    }
    let bytes = [UInt8](sealed)
    let ephemeralPublic = Data(bytes[magic.count..<(magic.count + point)])
    let combined = Data(bytes[(magic.count + point)...])
    let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: blob, authenticationContext: authenticationContext(reason))
    let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
    let secret = try enclaveKey.sharedSecretFromKeyAgreement(with: ephemeral)
    let key = derivedKey(secret, salt: ephemeralPublic, info: Data("orin-dx-pr-bot v1".utf8))
    let der = try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: key)
    return (der, enclaveKey.publicKey)
}

final class Outcome<T>: @unchecked Sendable {
    var value: T?
    var error: Error?
}

/// A user-presence check that is not tied to a key (used before sealing or replacing a key).
func requirePresence(reason: String, biometricOnly: Bool) throws {
    let context = LAContext()
    let policy: LAPolicy =
        biometricOnly ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
    var error: NSError?
    guard context.canEvaluatePolicy(policy, error: &error) else {
        throw EnclaveError("cannot ask for approval: \(error?.localizedDescription ?? "unavailable")")
    }
    let done = DispatchSemaphore(value: 0)
    let outcome = Outcome<Bool>()
    context.evaluatePolicy(policy, localizedReason: reason) { ok, error in
        outcome.value = ok
        outcome.error = error
        done.signal()
    }
    done.wait()
    guard outcome.value == true else {
        throw EnclaveError("not approved: \(outcome.error?.localizedDescription ?? "cancelled")")
    }
}

// MARK: - GitHub

func base64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

/// RS256 App JWT with fixed claims. Lives only in this process's memory.
func appJWT(signingWith key: SecKey) throws -> String {
    let now = Int(Date().timeIntervalSince1970)
    let header = base64URL(Data(#"{"alg":"RS256","typ":"JWT"}"#.utf8))
    let payload = base64URL(Data(#"{"iat":\#(now - 60),"exp":\#(now + 540),"iss":"\#(githubAppID)"}"#.utf8))
    let signingInput = "\(header).\(payload)"
    var error: Unmanaged<CFError>?
    guard
        let signature = SecKeyCreateSignature(
            key, .rsaSignatureMessagePKCS1v15SHA256, Data(signingInput.utf8) as CFData, &error) as Data?
    else {
        throw EnclaveError("signing failed: \(String(describing: error?.takeRetainedValue()))")
    }
    return "\(signingInput).\(base64URL(signature))"
}

final class RefuseRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

let session: URLSession = {
    let config = URLSessionConfiguration.ephemeral
    config.urlCache = nil
    config.httpCookieStorage = nil
    config.urlCredentialStorage = nil
    config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    config.timeoutIntervalForRequest = 30
    return URLSession(configuration: config, delegate: RefuseRedirects(), delegateQueue: nil)
}()

func github(_ method: String, _ path: String, bearer: String, body: [String: Any]? = nil) throws -> (
    Int, [String: Any]
) {
    guard let url = URL(string: "https://\(apiHost)\(path)"), url.host == apiHost, url.scheme == "https" else {
        throw EnclaveError("bad request path")
    }
    var request = URLRequest(url: url)
    request.httpMethod = method
    request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
    request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
    request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
    request.setValue("\(toolName)/\(toolVersion)", forHTTPHeaderField: "User-Agent")
    if let body {
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    let done = DispatchSemaphore(value: 0)
    let outcome = Outcome<(Int, Data)>()
    session.dataTask(with: request) { data, response, error in
        if let http = response as? HTTPURLResponse {
            outcome.value = (http.statusCode, data ?? Data())
        }
        outcome.error = error
        done.signal()
    }.resume()
    done.wait()
    guard let (status, data) = outcome.value else {
        throw EnclaveError("GitHub request failed: \(outcome.error?.localizedDescription ?? "no response")")
    }
    let json = data.isEmpty ? [:] : ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:])
    return (status, json)
}

func githubFailure(_ what: String, _ status: Int, _ json: [String: Any]) -> EnclaveError {
    EnclaveError("\(what): HTTP \(status) \((json["message"] as? String) ?? "")")
}

/// Best effort: revoke a token we refuse to hand out.
func revoke(_ token: String) {
    _ = try? github("DELETE", "/installation/token", bearer: token)
}

struct InstallationToken {
    let token: String
    let expiresAt: Date
}

func mintScopedToken(repo: String, key: SecKey) throws -> InstallationToken {
    let jwt = try appJWT(signingWith: key)
    let (lookupStatus, installation) = try github("GET", "/repos/\(githubOrg)/\(repo)/installation", bearer: jwt)
    guard lookupStatus == 200, let installationID = installation["id"] as? Int else {
        throw githubFailure("the App is not installed on \(githubOrg)/\(repo)", lookupStatus, installation)
    }
    let body: [String: Any] = ["repositories": [repo], "permissions": requestedPermissions]
    let (status, json) = try github(
        "POST", "/app/installations/\(installationID)/access_tokens", bearer: jwt, body: body)
    guard status == 201, let token = json["token"] as? String, let expiresText = json["expires_at"] as? String
    else { throw githubFailure("GitHub refused the token request", status, json) }

    // Refuse (and revoke) anything broader than what was asked for.
    let granted = json["permissions"] as? [String: String] ?? [:]
    let repos = (json["repositories"] as? [[String: Any]] ?? []).compactMap { ($0["name"] as? String)?.lowercased() }
    guard granted == requestedPermissions, repos == [repo.lowercased()] else {
        revoke(token)
        throw EnclaveError("GitHub returned a token with a different scope than requested; it was revoked")
    }
    guard token.utf8.count <= 512, token.allSatisfy({ $0.isASCII && !$0.isWhitespace }) else {
        revoke(token)
        throw EnclaveError("GitHub returned a token in an unexpected form")
    }
    guard let expiresAt = ISO8601DateFormatter().date(from: expiresText) else {
        revoke(token)
        throw EnclaveError("GitHub returned an unreadable expiry")
    }
    return InstallationToken(token: token, expiresAt: expiresAt)
}

// MARK: - Token cache (per repo, 0700 dir, 0600 files, at most `cacheLifetime` seconds)

func cachedToken(_ paths: Paths, repo: String) -> String? {
    guard (try? checkPrivateDir(paths.cacheDir)) != nil,
        let data = try? readPrivate(paths.cacheFile(repo), limit: 4096),
        let entry = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
        let cachedRepo = entry["repo"] as? String, cachedRepo == repo.lowercased(),
        let token = entry["token"] as? String, let useUntil = entry["use_until"] as? Double
    else { return nil }
    let now = Date().timeIntervalSince1970
    guard now < useUntil, useUntil - now <= cacheLifetime else { return nil }
    return token
}

func storeToken(_ paths: Paths, repo: String, _ minted: InstallationToken) {
    let useUntil = min(
        Date().timeIntervalSince1970 + cacheLifetime, minted.expiresAt.timeIntervalSince1970 - minRemainingLifetime)
    let entry: [String: Any] = ["repo": repo.lowercased(), "token": minted.token, "use_until": useUntil]
    do {
        try ensurePrivateDir(paths.cacheDir)
        try writePrivate(try JSONSerialization.data(withJSONObject: entry), to: paths.cacheFile(repo))
    } catch {
        note("warning: could not cache the token: \(error)")
    }
}

func purgeCache(_ dir: String, only repo: String? = nil) {
    guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
    for name in names {
        let match =
            repo.map { name == "token-\($0.lowercased()).json" }
            ?? (name.hasPrefix("token-") || name.hasPrefix("jwt") || name.hasPrefix(".tmp-")
                || name == "installation-id")
        if match { unlink(dir + "/" + name) }
    }
}

// MARK: - Commands

func validatedRepo(_ raw: String) -> String {
    var repo = raw
    if repo.hasPrefix(githubOrg + "/") { repo.removeFirst(githubOrg.count + 1) }
    guard repo.range(of: #"^[A-Za-z0-9._-]{1,100}$"#, options: .regularExpression) != nil,
        repo != ".", repo != ".."
    else { fail("invalid repo name (expected [A-Za-z0-9._-]+, optionally prefixed with \(githubOrg)/)", 2) }
    return repo
}

func loadSealed(_ paths: Paths) throws -> SealedKeyFile {
    guard exists(paths.stateDir) else { throw EnclaveError("no key sealed; run: \(toolName) seal < key.pem") }
    try checkPrivateDir(paths.stateDir)
    guard let data = try readPrivate(paths.sealedFile) else { throw EnclaveError("no key sealed") }
    return try SealedKeyFile.parse(data)
}

func token(_ rawRepo: String) {
    let repo = validatedRepo(rawRepo)
    let paths = resolvePaths()
    if let cached = cachedToken(paths, repo: repo) {
        print(cached)
        return
    }
    if !exists(paths.sealedFile) && exists(paths.legacySealed) {
        fail("found state from before the rename; run: \(toolName) migrate")
    }
    do {
        let file = try loadSealed(paths)
        var der = try unseal(file, reason: "mint a GitHub token for \(githubOrg)/\(repo)")
        let key = rsaPrivateKey(der)
        wipe(&der)
        guard let key else { fail("sealed data is not a usable RSA key") }
        let minted = try mintScopedToken(repo: repo, key: key)
        storeToken(paths, repo: repo, minted)
        print(minted.token)
    } catch let error as EnclaveError {
        fail(error.description)
    } catch {
        fail("could not unlock the key (cancelled, denied or unavailable): \(error)")
    }
}

func seal(replace: Bool, policy: ApprovalPolicy) {
    let paths = resolvePaths()
    var input = FileHandle.standardInput.readDataToEndOfFile()
    guard input.count <= 65536, var der = derFromPEM(input) else {
        wipe(&input)
        fail("stdin is not an RSA private key in PKCS#1 PEM form (BEGIN RSA PRIVATE KEY)")
    }
    wipe(&input)
    defer { wipe(&der) }
    guard let rsa = rsaPrivateKey(der), SecKeyGetBlockSize(rsa) >= 256 else {
        fail("stdin is not a usable RSA private key of at least 2048 bits")
    }
    let existing = exists(paths.sealedFile) || exists(paths.legacySealed)
    if existing && !replace { fail("a key is already sealed; pass --replace to overwrite it (asks for approval)") }
    guard SecureEnclave.isAvailable else { fail("this Mac has no Secure Enclave") }
    do {
        try requirePresence(
            reason: existing ? "replace the sealed GitHub App key" : "seal a GitHub App key",
            biometricOnly: policy == .biometryCurrentSet)
        try ensurePrivateDir(paths.stateDir)
        var accessError: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, policy.flags, &accessError)
        else { fail("could not create the access policy") }
        let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let (file, key) = try wrap(der, to: enclaveKey.publicKey, blob: enclaveKey.dataRepresentation, policy: policy)
        try writePrivate(file.encoded, to: paths.sealedFile)
        try verifyWritten(paths.sealedFile, key: key)
        // The old key (any layout) is superseded; tokens cached under it are dropped too.
        unlink(paths.legacySealed)
        unlink(paths.legacyBlob)
        rmdir(paths.legacyStateDir)
        purgeCache(paths.cacheDir)
        purgeCache(paths.legacyCacheDir)
        rmdir(paths.legacyCacheDir)
        print("sealed to the Secure Enclave (\(der.count) byte key; approval: \(policy.label))")
    } catch {
        fail("seal failed: \(error)")
    }
}

func migrate() {
    let paths = resolvePaths()
    if exists(paths.sealedFile) {
        print("already migrated")
        if exists(paths.legacySealed) {
            print("pre-rename files remain in \(paths.legacyStateDir); delete them once `token` works")
        }
        return
    }
    do {
        try checkPrivateDir(paths.legacyStateDir)
        guard let blob = try readPrivate(paths.legacyBlob), let sealed = try readPrivate(paths.legacySealed) else {
            fail("nothing to migrate: no pre-rename sealed key found")
        }
        // One prompt. The Secure Enclave key itself is reused; only its wrapping is upgraded to format 2.
        let legacy = try unsealLegacy(blob: blob, sealed: sealed, reason: "upgrade the sealed GitHub App key")
        var der = legacy.0
        let enclavePublic = legacy.1
        defer { wipe(&der) }
        guard rsaPrivateKey(der) != nil else { fail("legacy sealed data is not a usable RSA key") }
        try ensurePrivateDir(paths.stateDir)
        // Pre-rename keys were created with the userPresence policy.
        let (file, key) = try wrap(der, to: enclavePublic, blob: blob, policy: .userPresence)
        try writePrivate(file.encoded, to: paths.sealedFile)
        try verifyWritten(paths.sealedFile, key: key)
        unlink(paths.legacySealed)
        unlink(paths.legacyBlob)
        rmdir(paths.legacyStateDir)
        // The old cache held an App JWT and tokens on disk; drop them.
        purgeCache(paths.legacyCacheDir)
        rmdir(paths.legacyCacheDir)
        print("migrated: the same Secure Enclave key now wraps the App key in format 2")
    } catch let error as EnclaveError {
        fail("migration failed, nothing was removed: \(error.description)")
    } catch {
        fail("migration failed (cancelled, denied or unavailable), nothing was removed: \(error)")
    }
}

func status() {
    let paths = resolvePaths()
    if let data = try? readPrivate(paths.sealedFile), let file = try? SealedKeyFile.parse(data) {
        print("sealed (format 2; approval: \(file.policy.label))")
        exit(0)
    }
    if exists(paths.sealedFile) { fail("a sealed key file exists but cannot be read; check its permissions") }
    if exists(paths.legacySealed) {
        print("pre-rename key found; run: \(toolName) migrate")
        exit(3)
    }
    print("no key sealed")
    exit(1)
}

let usage = """
    usage: \(toolName) token <repo>
           \(toolName) seal [--replace] [--biometry-only]  < key.pem
           \(toolName) migrate
           \(toolName) forget [<repo>]
           \(toolName) status
           \(toolName) --version

      token    print an installation token for \(githubOrg)/<repo> with only pull_requests:write and
               contents:read, after Touch ID (a token minted in the last \(Int(cacheLifetime / 60)) minutes is reused)
      seal     seal a PKCS#1 PEM read from stdin to the Secure Enclave (asks for approval)
      migrate  upgrade state from before the rename, reusing the same Secure Enclave key (one prompt)
      forget   delete cached tokens (all, or one repo's)
      status   report whether a key is sealed (no prompt)
    """

umask(0o077)
let arguments = Array(CommandLine.arguments.dropFirst())
switch arguments.first {
case "token":
    guard arguments.count == 2 else { fail("usage: \(toolName) token <repo>", 2) }
    token(arguments[1])
case "seal":
    let flags = Set(arguments.dropFirst())
    guard flags.isSubset(of: ["--replace", "--biometry-only"]) else {
        fail("usage: \(toolName) seal [--replace] [--biometry-only]", 2)
    }
    seal(
        replace: flags.contains("--replace"),
        policy: flags.contains("--biometry-only") ? .biometryCurrentSet : .userPresence)
case "migrate":
    guard arguments.count == 1 else { fail("usage: \(toolName) migrate", 2) }
    migrate()
case "forget":
    guard arguments.count <= 2 else { fail("usage: \(toolName) forget [<repo>]", 2) }
    let paths = resolvePaths()
    purgeCache(paths.cacheDir, only: arguments.count == 2 ? validatedRepo(arguments[1]) : nil)
case "status":
    guard arguments.count == 1 else { fail("usage: \(toolName) status", 2) }
    status()
case "--version":
    print("\(toolName) \(toolVersion)")
case "-h", "--help", "help":
    print(usage)
default:
    fail("unknown command\n\(usage)", 2)
}
