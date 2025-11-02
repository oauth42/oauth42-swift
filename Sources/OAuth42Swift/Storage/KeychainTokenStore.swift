import Foundation
import Security

/// Keychain-based implementation of TokenStore for secure token persistence
public class KeychainTokenStore: TokenStore {
    private let service: String
    private let accessGroup: String?
    private let tokenKey = "oauth42_tokens"

    /// Initialize a Keychain token store
    /// - Parameters:
    ///   - service: The service identifier for Keychain items (typically bundle ID)
    ///   - accessGroup: Optional Keychain access group for sharing between apps
    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public func saveTokens(_ tokens: TokenResponse) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        guard let data = try? encoder.encode(tokens) else {
            throw OAuth42Error.keychainError("Failed to encode tokens")
        }

        // Delete any existing tokens first
        try? deleteTokens()

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tokenKey,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw OAuth42Error.keychainError("Failed to save to Keychain: \(status)")
        }
    }

    public func retrieveTokens() throws -> TokenResponse? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tokenKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            }
            throw OAuth42Error.keychainError("Failed to retrieve from Keychain: \(status)")
        }

        guard let data = result as? Data else {
            throw OAuth42Error.keychainError("Invalid data retrieved from Keychain")
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        do {
            return try decoder.decode(TokenResponse.self, from: data)
        } catch {
            throw OAuth42Error.keychainError("Failed to decode tokens: \(error.localizedDescription)")
        }
    }

    public func deleteTokens() throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tokenKey
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw OAuth42Error.keychainError("Failed to delete from Keychain: \(status)")
        }
    }
}
