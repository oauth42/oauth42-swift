import Foundation
import CryptoKit

/// Manages PKCE (Proof Key for Code Exchange) for OAuth2 Authorization Code Flow
public class PKCEManager {

    /// PKCE code verifier and challenge pair
    public struct PKCEPair {
        public let codeVerifier: String
        public let codeChallenge: String
        public let codeChallengeMethod: String = "S256"
    }

    /// Generate a new PKCE code verifier and challenge pair
    public static func generatePKCEPair() throws -> PKCEPair {
        // Generate a cryptographically secure random code verifier
        // Must be 43-128 characters from the unreserved character set
        let codeVerifier = generateCodeVerifier()

        // Create SHA256 hash of the verifier
        guard let verifierData = codeVerifier.data(using: .utf8) else {
            throw OAuth42Error.pkceGenerationFailed
        }

        let hash = SHA256.hash(data: verifierData)
        let codeChallenge = Data(hash)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        return PKCEPair(
            codeVerifier: codeVerifier,
            codeChallenge: codeChallenge
        )
    }

    /// Generate a cryptographically secure random code verifier
    private static func generateCodeVerifier() -> String {
        let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        let length = 128 // Maximum length for better entropy

        var verifier = ""
        for _ in 0..<length {
            let randomIndex = Int.random(in: 0..<characters.count)
            let character = characters[characters.index(characters.startIndex, offsetBy: randomIndex)]
            verifier.append(character)
        }

        return verifier
    }
}
