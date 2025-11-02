import Foundation

/// Login request for password-based authentication
/// Corresponds to login_request.schema.json
/// Used for first-party apps (like authenticator app) that need native login UI
public struct LoginRequest: Codable {
    public let email: String
    public let password: String
    public let mfaCode: String?
    public let rememberMe: Bool?

    enum CodingKeys: String, CodingKey {
        case email
        case password
        case mfaCode = "mfa_code"
        case rememberMe = "remember_me"
    }

    public init(email: String, password: String, mfaCode: String? = nil, rememberMe: Bool? = nil) {
        self.email = email
        self.password = password
        self.mfaCode = mfaCode
        self.rememberMe = rememberMe
    }
}
