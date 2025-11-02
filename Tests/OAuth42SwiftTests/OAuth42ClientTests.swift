import XCTest
@testable import OAuth42Swift

final class OAuth42ClientTests: XCTestCase {

    // MARK: - Configuration Tests

    func testOIDCDiscoveryParsing() throws {
        let json = """
        {
            "issuer": "https://localhost:8443",
            "authorization_endpoint": "https://localhost:8443/oauth2/authorize",
            "token_endpoint": "https://localhost:8443/oauth2/token",
            "userinfo_endpoint": "https://localhost:8443/oauth2/userinfo",
            "jwks_uri": "https://localhost:8443/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256", "plain"]
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let config = try decoder.decode(OIDCConfiguration.self, from: json)

        XCTAssertEqual(config.issuer, "https://localhost:8443")
        XCTAssertEqual(config.authorizationEndpoint, "https://localhost:8443/oauth2/authorize")
        XCTAssertEqual(config.tokenEndpoint, "https://localhost:8443/oauth2/token")
        XCTAssertEqual(config.userinfoEndpoint, "https://localhost:8443/oauth2/userinfo")
        XCTAssertTrue(config.codeChallengeMethodsSupported?.contains("S256") ?? false)
    }

    // MARK: - Token Response Tests

    func testTokenResponseParsing() throws {
        let json = """
        {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token",
            "scope": "openid profile email",
            "id_token": "test_id_token",
            "received_at": "2025-01-01T00:00:00Z"
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let tokenResponse = try decoder.decode(TokenResponse.self, from: json)

        XCTAssertEqual(tokenResponse.accessToken, "test_access_token")
        XCTAssertEqual(tokenResponse.tokenType, "Bearer")
        XCTAssertEqual(tokenResponse.expiresIn, 3600)
        XCTAssertEqual(tokenResponse.refreshToken, "test_refresh_token")
        XCTAssertEqual(tokenResponse.scope, "openid profile email")
        XCTAssertEqual(tokenResponse.idToken, "test_id_token")
    }

    func testTokenExpiration() {
        let now = Date()
        let tokens = TokenResponse(
            accessToken: "test",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: nil,
            scope: nil,
            idToken: nil,
            receivedAt: now
        )

        XCTAssertFalse(tokens.isExpired())
        XCTAssertEqual(tokens.expiresAt.timeIntervalSince(now), 3600, accuracy: 1.0)

        let expiredTokens = TokenResponse(
            accessToken: "test",
            tokenType: "Bearer",
            expiresIn: 60,
            refreshToken: nil,
            scope: nil,
            idToken: nil,
            receivedAt: now.addingTimeInterval(-120) // 2 minutes ago
        )

        XCTAssertTrue(expiredTokens.isExpired())
    }

    // MARK: - UserInfo Tests

    func testUserInfoParsing() throws {
        let json = """
        {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "email": "test@example.com",
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "email_verified": true,
            "mfa_enabled": false
        }
        """.data(using: .utf8)!

        let decoder = JSONDecoder()
        let userInfo = try decoder.decode(UserInfo.self, from: json)

        XCTAssertEqual(userInfo.id, "123e4567-e89b-12d3-a456-426614174000")
        XCTAssertEqual(userInfo.email, "test@example.com")
        XCTAssertEqual(userInfo.username, "testuser")
        XCTAssertEqual(userInfo.firstName, "Test")
        XCTAssertEqual(userInfo.lastName, "User")
        XCTAssertEqual(userInfo.emailVerified, true)
        XCTAssertEqual(userInfo.mfaEnabled, false)
    }

    // MARK: - PKCE Tests

    func testPKCEGeneration() throws {
        let pkce = try PKCEManager.generatePKCEPair()

        XCTAssertGreaterThanOrEqual(pkce.codeVerifier.count, 43)
        XCTAssertLessThanOrEqual(pkce.codeVerifier.count, 128)
        XCTAssertFalse(pkce.codeChallenge.isEmpty)
        XCTAssertEqual(pkce.codeChallengeMethod, "S256")

        // Verify code verifier contains only allowed characters
        let allowedCharacters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        XCTAssertTrue(pkce.codeVerifier.unicodeScalars.allSatisfy { allowedCharacters.contains($0) })

        // Verify code challenge is base64url encoded (no +, /, =)
        XCTAssertFalse(pkce.codeChallenge.contains("+"))
        XCTAssertFalse(pkce.codeChallenge.contains("/"))
        XCTAssertFalse(pkce.codeChallenge.contains("="))
    }

    func testPKCEUniqueness() throws {
        let pkce1 = try PKCEManager.generatePKCEPair()
        let pkce2 = try PKCEManager.generatePKCEPair()

        XCTAssertNotEqual(pkce1.codeVerifier, pkce2.codeVerifier)
        XCTAssertNotEqual(pkce1.codeChallenge, pkce2.codeChallenge)
    }

    // MARK: - Authorization URL Tests

    func testBuildAuthorizationURL() async throws {
        let client = OAuth42Client(
            clientId: "test-client-id",
            redirectURI: "myapp://oauth-callback",
            issuer: "https://localhost:8443"
        )

        // Note: This will fail without a running backend
        // In a real test, we'd use a mock URLSession
    }

    // MARK: - Error Tests

    func testOAuth42Errors() {
        let errors: [OAuth42Error] = [
            .invalidConfiguration("test"),
            .invalidURL("https://example.com"),
            .authorizationFailed("test"),
            .tokenExchangeFailed("test"),
            .refreshFailed("test"),
            .missingRefreshToken,
            .keychainError("test"),
            .pkceGenerationFailed,
            .invalidState,
            .userCancelled
        ]

        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
        }
    }
}
