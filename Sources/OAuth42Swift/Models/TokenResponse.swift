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

    /// The date when this token was received (client-side timestamp, not from backend)
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
        // Note: receivedAt is NOT part of the backend response - it's set client-side
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

    // Custom decoder - receivedAt is set client-side, not decoded from JSON
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        accessToken = try container.decode(String.self, forKey: .accessToken)
        tokenType = try container.decode(String.self, forKey: .tokenType)
        expiresIn = try container.decode(Int.self, forKey: .expiresIn)
        refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
        scope = try container.decodeIfPresent(String.self, forKey: .scope)
        idToken = try container.decodeIfPresent(String.self, forKey: .idToken)

        // Set receivedAt to current time (not from backend)
        receivedAt = Date()
    }

    // Custom encoder - don't encode receivedAt (it will be regenerated on decode)
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(accessToken, forKey: .accessToken)
        try container.encode(tokenType, forKey: .tokenType)
        try container.encode(expiresIn, forKey: .expiresIn)
        try container.encodeIfPresent(refreshToken, forKey: .refreshToken)
        try container.encodeIfPresent(scope, forKey: .scope)
        try container.encodeIfPresent(idToken, forKey: .idToken)
        // Note: receivedAt is NOT encoded - it will be set to Date() when decoded
    }
}
