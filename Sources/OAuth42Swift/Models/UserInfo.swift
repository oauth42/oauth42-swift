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
        case id
        case email
        case username
        case firstName = "first_name"
        case lastName = "last_name"
        case emailVerified = "email_verified"
        case mfaEnabled = "mfa_enabled"
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
