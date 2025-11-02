import Foundation

/// MFA-specific error when MFA code is required
public struct MFARequiredError: Codable {
    public let error: String
    public let errorDescription: String?
    public let mfaRequired: Bool

    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
        case mfaRequired = "mfa_required"
    }
}

/// MFA status information
/// Corresponds to mfaStatusResponse.schema.json
public struct MFAStatus: Codable {
    public let enabled: Bool
    public let verifiedAt: Date?
    public let lastUsedAt: Date?
    public let backupCodesRemaining: Int?

    enum CodingKeys: String, CodingKey {
        case enabled
        case verifiedAt = "verified_at"
        case lastUsedAt = "last_used_at"
        case backupCodesRemaining = "backup_codes_remaining"
    }
}
