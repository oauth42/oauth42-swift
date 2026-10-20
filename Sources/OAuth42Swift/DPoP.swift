import CryptoKit
import Foundation
import Security

/// An installation's RFC 9449 signing key. Never log or export its private material.
public final class DPoPKey {
    private let sign: (Data) throws -> Data
    public let publicJWK: [String: String]
    public let isHardwareBacked: Bool
    private let lock = NSLock()
    private var nonces: [String: String] = [:]

    init(publicKey: P256.Signing.PublicKey, hardware: Bool, sign: @escaping (Data) throws -> Data) {
        let bytes = publicKey.x963Representation
        publicJWK = ["kty": "EC", "crv": "P-256", "x": Self.base64(bytes[1..<33]), "y": Self.base64(bytes[33..<65])]
        isHardwareBacked = hardware
        self.sign = sign
    }

    public var thumbprint: String {
        let canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(publicJWK["x"]!)\",\"y\":\"\(publicJWK["y"]!)\"}"
        return Self.base64(Data(SHA256.hash(data: Data(canonical.utf8))))
    }

    /// Sign a fresh proof. URI query and fragment are excluded as required by RFC 9449.
    public func proof(method: String, url: URL, nonce: String? = nil, accessToken: String? = nil) throws -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw OAuth42Error.invalidURL("Invalid proof URI")
        }
        components.query = nil
        components.fragment = nil
        let uri = try SecurityPolicy.httpsURL(components.string ?? "")
        var claims: [String: Any] = ["jti": UUID().uuidString, "htm": method.uppercased(),
                                     "htu": uri.absoluteString, "iat": Int(Date().timeIntervalSince1970)]
        if let nonce = nonce { claims["nonce"] = nonce }
        if let accessToken = accessToken { claims["ath"] = Self.base64(Data(SHA256.hash(data: Data(accessToken.utf8)))) }
        let header: [String: Any] = ["typ": "dpop+jwt", "alg": "ES256", "jwk": publicJWK]
        let input = try Self.base64(JSONSerialization.data(withJSONObject: header, options: .sortedKeys)) + "." + Self.base64(JSONSerialization.data(withJSONObject: claims, options: .sortedKeys))
        return try input + "." + Self.base64(sign(Data(input.utf8)))
    }

    static func base64(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    func nonce(for key: String) -> String? {
        lock.lock(); defer { lock.unlock() }; return nonces[key]
    }
    func remember(_ nonce: String?, for key: String) -> Bool {
        guard let nonce = nonce, !nonce.isEmpty, nonce.utf8.count <= 128,
              nonce.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else { return false }
        lock.lock(); defer { lock.unlock() }
        if nonces.count >= 256 && nonces[key] == nil { nonces.removeAll() }
        nonces[key] = nonce
        return true
    }
}

/// Device-only Keychain storage. Load before resuming a session; create only for a fresh login.
/// Use a service scoped to the application's installation identifier (stored outside Keychain),
/// since Apple Keychain items can survive uninstall. Lost keys require fresh authentication.
public final class DPoPKeyStore {
    private let service: String
    public init(service: String) { self.service = service }
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: "oauth42_dpop_key", kSecAttrSynchronizable as String: false]
    }
    private struct Record: Codable { let hardware: Bool; let data: Data }

    public func load() throws -> DPoPKey? {
        var query = self.query
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = value as? Data else {
            throw OAuth42Error.keychainError("Cannot load DPoP key: \(status)")
        }
        let record = try JSONDecoder().decode(Record.self, from: data)
        return try Self.key(record)
    }

    /// Software fallback must be explicitly enabled for devices without Secure Enclave.
    /// Existing keys are never overwritten, and Secure Enclave failures never downgrade.
    public func create(allowSoftwareFallback: Bool = false) throws -> DPoPKey {
        let record: Record
        if SecureEnclave.isAvailable {
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil) else {
                throw OAuth42Error.keychainError("Cannot configure Secure Enclave access")
            }
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            record = Record(hardware: true, data: key.dataRepresentation)
        } else {
            guard allowSoftwareFallback else { throw OAuth42Error.invalidConfiguration("Secure Enclave is unavailable") }
            record = Record(hardware: false, data: P256.Signing.PrivateKey().rawRepresentation)
        }
        var query = self.query
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        query[kSecValueData as String] = try JSONEncoder().encode(record)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw OAuth42Error.keychainError("Cannot create DPoP key: \(status)") }
        return try Self.key(record)
    }

    /// Call after revoking/clearing the session, then discard clients holding the old key.
    public func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw OAuth42Error.keychainError("Cannot delete DPoP key: \(status)")
        }
    }
    private static func key(_ record: Record) throws -> DPoPKey {
        if record.hardware {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: record.data)
            return DPoPKey(publicKey: key.publicKey, hardware: true) { try key.signature(for: $0).rawRepresentation }
        }
        let key = try P256.Signing.PrivateKey(rawRepresentation: record.data)
        return DPoPKey(publicKey: key.publicKey, hardware: false) { try key.signature(for: $0).rawRepresentation }
    }
}
