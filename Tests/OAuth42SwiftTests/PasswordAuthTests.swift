import XCTest
@testable import OAuth42Swift

final class PasswordAuthTests: XCTestCase {

    // MARK: - Model Tests

    func testLoginRequestEncoding() throws {
        let request = LoginRequest(
            email: "test@example.com",
            password: "password123",
            mfaCode: "123456",
            rememberMe: true
        )

        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try encoder.encode(request)

        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["email"] as? String, "test@example.com")
        XCTAssertEqual(json?["password"] as? String, "password123")
        XCTAssertEqual(json?["mfa_code"] as? String, "123456")
        XCTAssertEqual(json?["remember_me"] as? Bool, true)
    }

    func testLoginRequestWithoutMFA() throws {
        let request = LoginRequest(
            email: "test@example.com",
            password: "password123"
        )

        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try encoder.encode(request)

        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["email"] as? String, "test@example.com")
        XCTAssertEqual(json?["password"] as? String, "password123")
        XCTAssertNil(json?["mfa_code"])
    }

    func testLoginResponseDecoding() throws {
        let json = """
        {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
            "user": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "test@example.com",
                "username": "testuser",
                "first_name": "Test",
                "last_name": "User",
                "email_verified": true,
                "mfa_enabled": true
            }
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()

        let response = try decoder.decode(LoginResponse.self, from: json)

        XCTAssertEqual(response.accessToken, "test_access_token")
        XCTAssertEqual(response.refreshToken, "test_refresh_token")
        XCTAssertEqual(response.expiresIn, 3600)
        XCTAssertEqual(response.user.email, "test@example.com")
        XCTAssertEqual(response.user.mfaEnabled, true)
    }

    func testLoginResponseToTokenResponse() throws {
        let userInfo = UserInfo(
            id: "user-123",
            email: "test@example.com",
            username: "testuser",
            firstName: "Test",
            lastName: "User",
            emailVerified: true,
            mfaEnabled: true
        )

        let loginResponse = LoginResponse(
            accessToken: "access_token",
            refreshToken: "refresh_token",
            expiresIn: 3600,
            user: userInfo,
            receivedAt: Date()
        )

        let tokenResponse = loginResponse.toTokenResponse()

        XCTAssertEqual(tokenResponse.accessToken, "access_token")
        XCTAssertEqual(tokenResponse.refreshToken, "refresh_token")
        XCTAssertEqual(tokenResponse.expiresIn, 3600)
        XCTAssertEqual(tokenResponse.tokenType, "Bearer")
    }

    func testLoginResponseExpiration() {
        let userInfo = UserInfo(
            id: "user-123",
            email: "test@example.com",
            username: nil,
            firstName: nil,
            lastName: nil,
            emailVerified: nil,
            mfaEnabled: nil
        )

        let now = Date()
        let loginResponse = LoginResponse(
            accessToken: "access",
            refreshToken: nil,
            expiresIn: 3600,
            user: userInfo,
            receivedAt: now
        )

        XCTAssertFalse(loginResponse.isExpired())
        XCTAssertEqual(loginResponse.expiresAt.timeIntervalSince(now), 3600, accuracy: 1.0)

        let expiredResponse = LoginResponse(
            accessToken: "access",
            refreshToken: nil,
            expiresIn: 60,
            user: userInfo,
            receivedAt: now.addingTimeInterval(-120)
        )

        XCTAssertTrue(expiredResponse.isExpired())
    }

    // MARK: - MFA Tests

    func testMFARequiredErrorDecoding() throws {
        let json = """
        {
            "error": "mfa_required",
            "error_description": "Multi-factor authentication is required",
            "mfa_required": true
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()

        let error = try decoder.decode(MFARequiredError.self, from: json)

        XCTAssertEqual(error.error, "mfa_required")
        XCTAssertEqual(error.errorDescription, "Multi-factor authentication is required")
        XCTAssertTrue(error.mfaRequired)
    }

    func testMFAStatusDecoding() throws {
        let json = """
        {
            "enabled": true,
            "verified_at": "2025-01-01T00:00:00Z",
            "last_used_at": "2025-01-02T12:00:00Z",
            "backup_codes_remaining": 5
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let status = try decoder.decode(MFAStatus.self, from: json)

        XCTAssertTrue(status.enabled)
        XCTAssertNotNil(status.verifiedAt)
        XCTAssertNotNil(status.lastUsedAt)
        XCTAssertEqual(status.backupCodesRemaining, 5)
    }

    func testMFAStatusDisabled() throws {
        let json = """
        {
            "enabled": false
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()

        let status = try decoder.decode(MFAStatus.self, from: json)

        XCTAssertFalse(status.enabled)
        XCTAssertNil(status.verifiedAt)
        XCTAssertNil(status.lastUsedAt)
    }

    // MARK: - Error Tests

    func testPasswordAuthErrors() {
        let errors: [OAuth42Error] = [
            .mfaRequired("MFA code required"),
            .invalidCredentials("Invalid username or password"),
            .loginFailed("Login failed")
        ]

        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
        }
    }

    // MARK: - UserInfo Initializer Test

    func testUserInfoInitializer() {
        let userInfo = UserInfo(
            id: "123",
            email: "test@example.com",
            username: "testuser",
            firstName: "Test",
            lastName: "User",
            emailVerified: true,
            mfaEnabled: false
        )

        XCTAssertEqual(userInfo.id, "123")
        XCTAssertEqual(userInfo.email, "test@example.com")
        XCTAssertEqual(userInfo.username, "testuser")
        XCTAssertEqual(userInfo.firstName, "Test")
        XCTAssertEqual(userInfo.lastName, "User")
        XCTAssertEqual(userInfo.emailVerified, true)
        XCTAssertEqual(userInfo.mfaEnabled, false)
    }
}
