import XCTest
@testable import OAuth42Swift

/// Integration tests that require the OAuth42 backend to be running
/// Run these tests with the backend started:
///   cd ~/localdev/oauth42
///   make up-local-dev-ssl
///   make run-local-oauth42
///
/// These tests use a test client that should be configured in the backend
final class IntegrationTests: XCTestCase {

    let testIssuer = "https://localhost:8443"
    let testClientId = "test-client-id"  // Must be configured in backend
    let testClientSecret = "test-client-secret"  // Must be configured in backend
    let testRedirectURI = "oauth42sdk://test-callback"

    // MARK: - Helper to check if backend is available

    func isBackendAvailable() async -> Bool {
        guard let url = URL(string: "\(testIssuer)/health") else {
            return false
        }

        do {
            // Create URLSession that accepts self-signed certificates
            let configuration = URLSessionConfiguration.default
            let session = URLSession(configuration: configuration, delegate: SelfSignedCertificateDelegate(), delegateQueue: nil)

            let (data, response) = try await session.data(from: url)

            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else {
                return false
            }

            // Check for expected health response
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
               json["status"] == "ok" {
                return true
            }

            return false
        } catch {
            print("Backend not available: \(error.localizedDescription)")
            return false
        }
    }

    // MARK: - Integration Tests

    func testOIDCDiscovery() async throws {
        guard await isBackendAvailable() else {
            throw XCTSkip("Backend not running. Start with: make up-local-dev-ssl && make run-local-oauth42")
        }

        let session = URLSession(configuration: .default, delegate: SelfSignedCertificateDelegate(), delegateQueue: nil)
        let client = OAuth42Client(
            clientId: testClientId,
            clientSecret: testClientSecret,
            redirectURI: testRedirectURI,
            issuer: testIssuer,
            urlSession: session
        )

        let config = try await client.fetchConfiguration()

        XCTAssertEqual(config.issuer, testIssuer)
        XCTAssertTrue(config.authorizationEndpoint.hasPrefix(testIssuer))
        XCTAssertTrue(config.tokenEndpoint.hasPrefix(testIssuer))
        XCTAssertNotNil(config.userinfoEndpoint)
        XCTAssertNotNil(config.jwksUri)
        XCTAssertTrue(config.codeChallengeMethodsSupported?.contains("S256") ?? false)
    }

    func testBuildAuthorizationURLWithBackend() async throws {
        guard await isBackendAvailable() else {
            throw XCTSkip("Backend not running")
        }

        let session = URLSession(configuration: .default, delegate: SelfSignedCertificateDelegate(), delegateQueue: nil)
        let client = OAuth42Client(
            clientId: testClientId,
            clientSecret: testClientSecret,
            redirectURI: testRedirectURI,
            issuer: testIssuer,
            urlSession: session
        )

        let authURL = try await client.buildAuthorizationURL()

        XCTAssertTrue(authURL.absoluteString.hasPrefix(testIssuer))
        XCTAssertTrue(authURL.absoluteString.contains("client_id=\(testClientId)"))
        XCTAssertTrue(authURL.absoluteString.contains("redirect_uri="))
        XCTAssertTrue(authURL.absoluteString.contains("code_challenge="))
        XCTAssertTrue(authURL.absoluteString.contains("code_challenge_method=S256"))
        XCTAssertTrue(authURL.absoluteString.contains("state="))
    }

    // NOTE: Full OAuth flow integration tests would require:
    // 1. Automated browser interaction or mock authorization server
    // 2. Test user credentials
    // 3. Ability to complete the authorization flow programmatically
    //
    // These are typically done with end-to-end testing tools or
    // by mocking the authorization server responses.
}

/// URLSessionDelegate that accepts self-signed certificates for local development
class SelfSignedCertificateDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Only accept self-signed certificates for localhost
        if challenge.protectionSpace.host == "localhost" || challenge.protectionSpace.host == "127.0.0.1" {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }

        completionHandler(.performDefaultHandling, nil)
    }
}
