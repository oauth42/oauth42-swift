import Foundation

/// User Information from OAuth42 userinfo endpoint
/// Corresponds to user_info.schema.json
public struct UserInfo: Codable {
    public let id: String
    public let email: String
    public let username: String?
    public let firstName: String?
    public let lastName: String?
    public let emailVerified: Bool?
    public let mfaEnabled: Bool?

    enum CodingKeys: String, CodingKey {
        case sub  // OIDC standard uses "sub" for subject/user ID
        case id   // Login response uses "id"
        case email
        case username
        case firstName = "first_name"
        case lastName = "last_name"
        case emailVerified = "email_verified"
        case mfaEnabled = "mfa_enabled"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        // Try "sub" first (OIDC userinfo), then "id" (login response)
        if let sub = try? container.decode(String.self, forKey: .sub) {
            self.id = sub
        } else {
            self.id = try container.decode(String.self, forKey: .id)
        }

        self.email = try container.decode(String.self, forKey: .email)
        self.username = try container.decodeIfPresent(String.self, forKey: .username)
        self.firstName = try container.decodeIfPresent(String.self, forKey: .firstName)
        self.lastName = try container.decodeIfPresent(String.self, forKey: .lastName)
        self.emailVerified = try container.decodeIfPresent(Bool.self, forKey: .emailVerified)
        self.mfaEnabled = try container.decodeIfPresent(Bool.self, forKey: .mfaEnabled)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .sub)
        try container.encode(email, forKey: .email)
        try container.encodeIfPresent(username, forKey: .username)
        try container.encodeIfPresent(firstName, forKey: .firstName)
        try container.encodeIfPresent(lastName, forKey: .lastName)
        try container.encodeIfPresent(emailVerified, forKey: .emailVerified)
        try container.encodeIfPresent(mfaEnabled, forKey: .mfaEnabled)
    }

    public init(
        id: String,
        email: String,
        username: String? = nil,
        firstName: String? = nil,
        lastName: String? = nil,
        emailVerified: Bool? = nil,
        mfaEnabled: Bool? = nil
    ) {
        self.id = id
        self.email = email
        self.username = username
        self.firstName = firstName
        self.lastName = lastName
        self.emailVerified = emailVerified
        self.mfaEnabled = mfaEnabled
    }
}
