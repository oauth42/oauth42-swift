import Foundation

/// Login response from password-based authentication
/// Corresponds to login_response.schema.json
public struct LoginResponse: Codable {
    public let accessToken: String
    public let refreshToken: String?
    public let expiresIn: Int
    public let user: UserInfo

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

    /// Convert to TokenResponse for unified token handling
    public func toTokenResponse() -> TokenResponse {
        return TokenResponse(
            accessToken: accessToken,
            tokenType: "Bearer",
            expiresIn: expiresIn,
            refreshToken: refreshToken,
            scope: nil,
            idToken: nil,
            receivedAt: receivedAt
        )
    }

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case user
    }

    public init(accessToken: String, refreshToken: String?, expiresIn: Int, user: UserInfo, receivedAt: Date = Date()) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
        self.user = user
        self.receivedAt = receivedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accessToken = try container.decode(String.self, forKey: .accessToken)
        refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
        expiresIn = try container.decode(Int.self, forKey: .expiresIn)
        user = try container.decode(UserInfo.self, forKey: .user)
        receivedAt = Date() // Always set to current time when decoding
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(accessToken, forKey: .accessToken)
        try container.encodeIfPresent(refreshToken, forKey: .refreshToken)
        try container.encode(expiresIn, forKey: .expiresIn)
        try container.encode(user, forKey: .user)
        // Don't encode receivedAt
    }
}
