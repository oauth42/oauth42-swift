import Foundation

/// Errors that can occur during OAuth42 operations
public enum OAuth42Error: Error, LocalizedError {
    case invalidConfiguration(String)
    case invalidURL(String)
    case networkError(Error)
    case invalidResponse(String)
    case authorizationFailed(String)
    case tokenExchangeFailed(String)
    case refreshFailed(String)
    case missingRefreshToken
    case keychainError(String)
    case pkceGenerationFailed
    case invalidState
    case userCancelled
    case mfaRequired(String)
    case invalidCredentials(String)
    case loginFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let message):
            return "Invalid configuration: \(message)"
        case .invalidURL(let url):
            return "Invalid URL: \(url)"
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .invalidResponse(let message):
            return "Invalid response: \(message)"
        case .authorizationFailed(let message):
            return "Authorization failed: \(message)"
        case .tokenExchangeFailed(let message):
            return "Token exchange failed: \(message)"
        case .refreshFailed(let message):
            return "Token refresh failed: \(message)"
        case .missingRefreshToken:
            return "No refresh token available"
        case .keychainError(let message):
            return "Keychain error: \(message)"
        case .pkceGenerationFailed:
            return "Failed to generate PKCE parameters"
        case .invalidState:
            return "Invalid state parameter - possible CSRF attack"
        case .userCancelled:
            return "User cancelled authentication"
        case .mfaRequired(let message):
            return "MFA code required: \(message)"
        case .invalidCredentials(let message):
            return "Invalid credentials: \(message)"
        case .loginFailed(let message):
            return "Login failed: \(message)"
        }
    }
}

/// OAuth2 error response from server
struct OAuth2ErrorResponse: Codable {
    let error: String
    let errorDescription: String?
    let errorUri: String?

    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
        case errorUri = "error_uri"
    }
}
