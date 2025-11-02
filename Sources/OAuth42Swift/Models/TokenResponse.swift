import Foundation

/// OAuth2 Token Response
/// Corresponds to token_response.schema.json
public struct TokenResponse: Codable {
    public let accessToken: String
    public let tokenType: String
    public let expiresIn: Int
    public let refreshToken: String?
    public let scope: String?
    public let idToken: String?

    /// The date when this token was received
    public let receivedAt: Date

    /// Computed expiration date
    public var expiresAt: Date {
        return receivedAt.addingTimeInterval(TimeInterval(expiresIn))
    }

    /// Check if the token is expired or will expire within the given threshold
    public func isExpired(threshold: TimeInterval = 60) -> Bool {
        return Date().addingTimeInterval(threshold) >= expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case scope
        case idToken = "id_token"
        case receivedAt = "received_at"
    }

    public init(accessToken: String, tokenType: String, expiresIn: Int, refreshToken: String?, scope: String?, idToken: String?, receivedAt: Date = Date()) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.scope = scope
        self.idToken = idToken
        self.receivedAt = receivedAt
    }
}
