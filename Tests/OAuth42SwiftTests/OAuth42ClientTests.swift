import Foundation
import XCTest
@testable import OAuth42Swift

final class OAuth42ClientTests: XCTestCase {
    override func tearDown() {
        MockURLProtocol.requestHandler = nil
        super.tearDown()
    }

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
        _ = OAuth42Client(
            clientId: "test-client-id",
            redirectURI: "myapp://oauth-callback",
            issuer: "https://localhost:8443"
        )

        // Note: This will fail without a running backend
        // In a real test, we'd use a mock URLSession
    }

    func testFetchHostedSocialProvidersUsesHostedAuthBaseURL() async throws {
        let session = makeMockSession()
        var requestedURLs: [String] = []
        MockURLProtocol.requestHandler = { request in
            requestedURLs.append(request.url!.absoluteString)

            if request.url?.path == "/.well-known/openid-configuration" {
                return (
                    HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                    Self.oidcConfigurationJSON()
                )
            }

            XCTAssertEqual(request.url?.host, "auth.oauth42.com")
            XCTAssertEqual(request.url?.path, "/api/social-providers")
            XCTAssertEqual(
                URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?
                    .queryItems?
                    .first(where: { $0.name == "client_id" })?
                    .value,
                "test-client-id"
            )

            return (
                HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                #"{"providers":["Google","github","apple","google",""]}"#.data(using: .utf8)!
            )
        }

        let client = OAuth42Client(
            clientId: "test-client-id",
            redirectURI: "myapp://oauth-callback",
            issuer: "https://api.oauth42.com",
            hostedAuthBaseURL: "https://auth.oauth42.com",
            urlSession: session
        )

        let providers = try await client.fetchHostedSocialProviders()

        XCTAssertEqual(providers, ["google", "github", "apple"])
        XCTAssertEqual(requestedURLs.first, "https://api.oauth42.com/.well-known/openid-configuration")
        XCTAssertEqual(requestedURLs.last?.hasPrefix("https://auth.oauth42.com/api/social-providers"), true)
    }

    func testBuildHostedSocialAuthorizationURLPostsInitRequest() async throws {
        let session = makeMockSession()
        var initRequestBody: [String: Any]?
        MockURLProtocol.requestHandler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                return (
                    HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                    Self.oidcConfigurationJSON()
                )
            }

            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.absoluteString, "https://auth.oauth42.com/api/social-auth/init")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")

            let body = try XCTUnwrap(Self.httpBodyData(from: request))
            initRequestBody = try JSONSerialization.jsonObject(with: body) as? [String: Any]

            return (
                HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                #"{"authorization_url":"https://accounts.google.com/o/oauth2/v2/auth?client_id=google","state":"server-state"}"#.data(using: .utf8)!
            )
        }

        let client = OAuth42Client(
            clientId: "test-client-id",
            redirectURI: "myapp://oauth-callback",
            issuer: "https://api.oauth42.com",
            hostedAuthBaseURL: "https://auth.oauth42.com",
            urlSession: session
        )

        let url = try await client.buildHostedSocialAuthorizationURL(
            provider: "Google",
            isSignup: true,
            state: "state-123"
        )

        XCTAssertEqual(url.absoluteString, "https://accounts.google.com/o/oauth2/v2/auth?client_id=google")
        XCTAssertEqual(initRequestBody?["provider"] as? String, "google")
        XCTAssertEqual(initRequestBody?["client_id"] as? String, "test-client-id")
        XCTAssertEqual(initRequestBody?["redirect_uri"] as? String, "myapp://oauth-callback")
        XCTAssertEqual(initRequestBody?["state"] as? String, "state-123")
        XCTAssertEqual(initRequestBody?["is_signup"] as? Bool, true)
    }

    func testHostedSocialRejectsInvalidIssuerHost() async throws {
        let session = makeMockSession()
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.absoluteString, "https://tahoeaccess.oauth42.com/.well-known/openid-configuration")
            return (
                HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!,
                Data()
            )
        }

        let client = OAuth42Client(
            clientId: "test-client-id",
            redirectURI: "myapp://oauth-callback",
            issuer: "https://tahoeaccess.oauth42.com",
            hostedAuthBaseURL: "https://auth.oauth42.com",
            urlSession: session
        )

        do {
            _ = try await client.fetchHostedSocialProviders()
            XCTFail("Expected invalid issuer error")
        } catch OAuth42Error.invalidIssuer(let message) {
            XCTAssertTrue(message.contains("OIDC discovery was not found"))
            XCTAssertTrue(message.contains("https://api.oauth42.com"))
        } catch {
            XCTFail("Expected invalid issuer error, got \(error)")
        }
    }

    // MARK: - Automatic Token Refresh Tests

    func testTokenExpirationDetection() throws {
        // Test that expired tokens are properly detected
        let expiredToken = TokenResponse(
            accessToken: "expired_token",
            tokenType: "Bearer",
            expiresIn: 60,
            refreshToken: "refresh_token",
            scope: nil,
            idToken: nil,
            receivedAt: Date().addingTimeInterval(-120) // 2 minutes ago
        )

        XCTAssertTrue(expiredToken.isExpired())
        XCTAssertTrue(expiredToken.isExpired(threshold: 0))
        XCTAssertTrue(expiredToken.isExpired(threshold: 60))
    }

    func testTokenNotExpiredWithinThreshold() throws {
        // Test that tokens within expiration threshold are considered expired
        let almostExpiredToken = TokenResponse(
            accessToken: "almost_expired",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "refresh_token",
            scope: nil,
            idToken: nil,
            receivedAt: Date().addingTimeInterval(-3550) // 10 seconds until expiry
        )

        // Should be expired with default 60 second threshold
        XCTAssertTrue(almostExpiredToken.isExpired())

        // Should not be expired with 0 second threshold
        XCTAssertFalse(almostExpiredToken.isExpired(threshold: 0))
    }

    func testFreshTokenNotExpired() throws {
        // Test that fresh tokens are not considered expired
        let freshToken = TokenResponse(
            accessToken: "fresh_token",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "refresh_token",
            scope: nil,
            idToken: nil,
            receivedAt: Date()
        )

        XCTAssertFalse(freshToken.isExpired())
    }

    // MARK: - Error Tests

    func testOAuth42Errors() {
        let errors: [OAuth42Error] = [
            .invalidConfiguration("test"),
            .invalidIssuer("test"),
            .invalidURL("https://example.com"),
            .authorizationFailed("test"),
            .hostedSocialAuthFailed("test"),
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

    private func makeMockSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    private static func oidcConfigurationJSON() -> Data {
        """
        {
            "issuer": "https://api.oauth42.com",
            "authorization_endpoint": "https://api.oauth42.com/oauth2/authorize",
            "token_endpoint": "https://api.oauth42.com/oauth2/token",
            "userinfo_endpoint": "https://api.oauth42.com/oauth2/userinfo",
            "jwks_uri": "https://api.oauth42.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"]
        }
        """.data(using: .utf8)!
    }

    private static func httpBodyData(from request: URLRequest) -> Data? {
        if let body = request.httpBody {
            return body
        }

        guard let bodyStream = request.httpBodyStream else {
            return nil
        }

        bodyStream.open()
        defer { bodyStream.close() }

        var data = Data()
        let bufferSize = 1_024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        while bodyStream.hasBytesAvailable {
            let count = bodyStream.read(buffer, maxLength: bufferSize)
            if count <= 0 {
                break
            }
            data.append(buffer, count: count)
        }

        return data
    }
}

private final class MockURLProtocol: URLProtocol {
    static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let handler = Self.requestHandler else {
            client?.urlProtocol(self, didFailWithError: OAuth42Error.invalidConfiguration("Missing mock handler"))
            return
        }

        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
