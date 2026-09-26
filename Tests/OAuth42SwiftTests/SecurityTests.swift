import CryptoKit
import Security
import XCTest

@testable import OAuth42Swift

final class SecurityTests: XCTestCase {
    private let issuer = "https://issuer.example"
    private var store: MemoryStore!
    private var session: URLSession!
    override func setUp() {
        store = MemoryStore()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [SecurityURLProtocol.self]
        session = URLSession(configuration: config)
    }
    override func tearDown() {
        SecurityURLProtocol.handler = nil
        session.invalidateAndCancel()
    }
    private func client(scopes: [String] = ["email"], issuer: String? = nil) -> OAuth42Client {
        OAuth42Client(
            clientId: "client", clientSecret: "s&=+雪", redirectURI: "app://callback?x=1&y=2",
            issuer: issuer ?? self.issuer, scopes: scopes, tokenStore: store, urlSession: session)
    }
    private func configuration(_ changes: [String: Any] = [:]) throws -> Data {
        var value: [String: Any] = [
            "issuer": issuer, "authorization_endpoint": issuer + "/authorize",
            "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
            "userinfo_endpoint": issuer + "/userinfo",
            "response_types_supported": ["code"], "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
        ]
        value.merge(changes) { _, new in new }
        return try JSONSerialization.data(withJSONObject: value)
    }
    private func response(_ request: URLRequest, _ data: Data, status: Int = 200) -> (
        HTTPURLResponse, Data
    ) {
        (
            HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!,
            data
        )
    }
    private var tokens: Data {
        Data(
            #"{"access_token":"access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh"}"#
                .utf8)
    }
    private func assertRejected(
        _ operation: () async throws -> Void, file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            try await operation()
            XCTFail("Expected rejection", file: file, line: line)
        } catch {}
    }

    func testDiscoveryRejectsIssuerMixupAndCredentialEndpoints() async throws {
        for changes in [
            ["issuer": "https://attacker.example"], ["token_endpoint": "https://attacker.example/token"],
            ["jwks_uri": "http://issuer.example/keys"],
            ["userinfo_endpoint": "https://issuer.example@attacker.example/u"],
            ["authorization_endpoint": "https://issuer.example/a#fragment"],
        ] {
            let data = try configuration(changes)
            SecurityURLProtocol.handler = { self.response($0, data) }
            await assertRejected { _ = try await self.client().fetchConfiguration() }
        }
        SecurityURLProtocol.handler = { _ in
            XCTFail("Insecure issuer must not be contacted")
            throw URLError(.badURL)
        }
        await assertRejected {
            _ = try await self.client(issuer: "http://issuer.example").fetchConfiguration()
        }
    }

    func testFormEncodingAndSingleUseStateIncludingFailure() async throws {
        let c = client()
        let config = try configuration()
        var calls = 0
        SecurityURLProtocol.handler = { request in
            if request.url!.path.contains("well-known") { return self.response(request, config) }
            calls += 1
            let body = String(decoding: Self.body(request), as: UTF8.self)
            XCTAssertTrue(body.contains("client_secret=s%26%3D%2B%E9%9B%AA"))
            XCTAssertTrue(body.contains("code=a%26grant_type%3Dpassword%2B"))
            XCTAssertTrue(body.contains("redirect_uri=app%3A%2F%2Fcallback%3Fx%3D1%26y%3D2"))
            return self.response(request, Data(), status: 400)
        }
        _ = try await c.buildAuthorizationURL(state: "expected")
        await assertRejected { _ = try await c.exchangeCodeForTokens(code: "wrong", state: "mismatch") }
        XCTAssertEqual(calls, 0)
        await assertRejected {
            _ = try await c.exchangeCodeForTokens(code: "a&grant_type=password+", state: "expected")
        }
        await assertRejected { _ = try await c.exchangeCodeForTokens(code: "again", state: "expected") }
        XCTAssertEqual(calls, 1)
        XCTAssertNil(try store.retrieveTokens())
    }

    func testLogoutInvalidatesInFlightRefreshAndPendingLogin() async throws {
        let c = client()
        let config = try configuration()
        SecurityURLProtocol.handler = { request in
            if request.url!.path.contains("well-known") { return self.response(request, config) }
            try c.clearTokens()  // Deterministic race: logout while response is in flight.
            return self.response(request, self.tokens)
        }
        _ = try await c.buildAuthorizationURL(state: "pending")
        await assertRejected { _ = try await c.refreshTokens(refreshToken: "old") }
        XCTAssertNil(try store.retrieveTokens())
        await assertRejected { _ = try await c.exchangeCodeForTokens(code: "code", state: "pending") }
    }

    func testConcurrentCodeExchangeAndRefreshCannotReuseCredential() async throws {
        let c = client()
        let config = try configuration()
        let entered = expectation(description: "request in flight")
        let release = DispatchSemaphore(value: 0)
        var calls = 0
        SecurityURLProtocol.handler = { request in
            if request.url!.path.contains("well-known") { return self.response(request, config) }
            calls += 1
            entered.fulfill()
            _ = release.wait(timeout: .now() + 5)
            return self.response(request, self.tokens)
        }
        _ = try await c.buildAuthorizationURL(state: "single")
        let first = Task { try await c.exchangeCodeForTokens(code: "code", state: "single") }
        await fulfillment(of: [entered], timeout: 3)
        await assertRejected { _ = try await c.exchangeCodeForTokens(code: "code", state: "single") }
        await assertRejected { _ = try await c.refreshTokens(refreshToken: "refresh") }
        release.signal()
        _ = try await first.value
        XCTAssertEqual(calls, 1)
    }

    func testMissingIDTokenAndInvalidTokenResponseNeverPersist() async throws {
        let config = try configuration()
        for data in [
            tokens, Data(#"{"access_token":"","token_type":"Bearer","expires_in":3600}"#.utf8),
            Data(#"{"access_token":"a","token_type":"MAC","expires_in":3600}"#.utf8),
            Data(#"{"access_token":"a","token_type":"Bearer","expires_in":-1}"#.utf8),
        ] {
            SecurityURLProtocol.handler = {
                self.response($0, $0.url!.path.contains("well-known") ? config : data)
            }
            let c = client(scopes: ["openid"])
            let url = try await c.buildAuthorizationURL(state: "s")
            XCTAssertNotNil(
                URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first {
                    $0.name == "nonce"
                }?.value)
            await assertRejected { _ = try await c.exchangeCodeForTokens(code: "c", state: "s") }
            XCTAssertNil(try store.retrieveTokens())
        }
    }

    func testResourceBearerIsRestrictedToTrustedHTTPSOrigins() async throws {
        try store.saveTokens(JSONDecoder().decode(TokenResponse.self, from: tokens))
        var called = false
        SecurityURLProtocol.handler = {
            called = true
            return self.response($0, Data())
        }
        let c = client()
        for value in [
            "https://evil.example/data", "http://issuer.example/data", "https://issuer.example:444/data",
        ] {
            await assertRejected { _ = try await c.makeAuthenticatedRequest(url: URL(string: value)!) }
        }
        XCTAssertFalse(called)
        _ = try await c.makeAuthenticatedRequest(url: URL(string: issuer + "/data")!)
        XCTAssertTrue(called)
    }

    func testSignedIDTokenValidationAndNegativeClaims() throws {
        let fixture = try SignedIDTokenFixture()
        try fixture.validate()
        for changes: [String: Any] in [
            ["iss": "https://evil.example"], ["aud": "other"], ["exp": 1],
            ["iat": Date().timeIntervalSince1970 + 600], ["nonce": "wrong"], ["sub": ""], ["exp": true],
            ["aud": ["client", "other"]], ["azp": "other"], ["nbf": Date().timeIntervalSince1970 + 600],
            ["at_hash": "bad"],
        ] {
            XCTAssertThrowsError(try fixture.validate(changes))
        }
        for header in [
            ["alg": "none"], ["alg": "HS256"], ["kid": "unknown"], ["jku": "https://evil.example/keys"],
            ["crit": ["x"]],
        ] as [[String: Any]] {
            XCTAssertThrowsError(try fixture.validate(header: header))
        }
        let token = try fixture.token()
        var parts = token.split(separator: ".").map(String.init)
        parts[1] = SignedIDTokenFixture.base64(Data(#"{"sub":"attacker"}"#.utf8))
        XCTAssertThrowsError(try fixture.validate(raw: parts.joined(separator: ".")))
        XCTAssertThrowsError(try fixture.validate(raw: "not.a.jwt"))
        try fixture.validate(["aud": ["client", "other"], "azp": "client"])
    }

    func testValidOIDCExchangeVerifiesNonceBeforeSaving() async throws {
        let fixture = try SignedIDTokenFixture()
        let config = try configuration()
        SecurityURLProtocol.handler = { request in
            switch request.url!.path {
            case "/.well-known/openid-configuration": return self.response(request, config)
            case "/jwks": return self.response(request, fixture.jwks)
            default:
                let data = try JSONSerialization.data(withJSONObject: [
                    "access_token": "access", "token_type": "Bearer",
                    "expires_in": 3600, "id_token": fixture.token(),
                ])
                return self.response(request, data)
            }
        }
        let c = client(scopes: ["openid"])
        _ = try await c.buildAuthorizationURL(state: "s", nonce: "nonce")
        let result = try await c.exchangeCodeForTokens(code: "code", state: "s")
        XCTAssertEqual(try store.retrieveTokens()?.idToken, result.idToken)
    }

    func testRefreshRetainsOmittedCredentialsAndRejectsSubjectChange() async throws {
        let fixture = try SignedIDTokenFixture()
        let original = TokenResponse(
            accessToken: "old", tokenType: "Bearer", expiresIn: 3600,
            refreshToken: "refresh", scope: "openid", idToken: try fixture.token())
        try store.saveTokens(original)
        let config = try configuration()
        var changeSubject = false
        SecurityURLProtocol.handler = { request in
            if request.url!.path.contains("well-known") { return self.response(request, config) }
            if request.url!.path == "/jwks" { return self.response(request, fixture.jwks) }
            var result: [String: Any] = [
                "access_token": "access", "token_type": "Bearer", "expires_in": 3600,
            ]
            if changeSubject { result["id_token"] = try fixture.token(["sub": "different-user"]) }
            return self.response(request, try JSONSerialization.data(withJSONObject: result))
        }
        let c = client(scopes: ["openid"])
        let refreshed = try await c.refreshTokens()
        XCTAssertEqual(refreshed.refreshToken, "refresh")
        XCTAssertEqual(refreshed.idToken, original.idToken)
        changeSubject = true
        await assertRejected { _ = try await c.refreshTokens() }
        XCTAssertEqual(try store.retrieveTokens()?.idToken, original.idToken)
    }

    func testUserinfoCannotSubstituteAuthenticatedSubject() async throws {
        let fixture = try SignedIDTokenFixture()
        try store.saveTokens(
            TokenResponse(
                accessToken: "access", tokenType: "Bearer", expiresIn: 3600,
                refreshToken: nil, scope: "openid", idToken: try fixture.token()))
        let config = try configuration()
        SecurityURLProtocol.handler = { request in
            self.response(
                request,
                request.url!.path.contains("well-known")
                    ? config : Data(#"{"sub":"attacker","email":"attacker@example.com"}"#.utf8))
        }
        await assertRejected { _ = try await self.client().fetchUserInfo() }
    }

    func testPasswordAuthenticationDoesNotWriteSecretsToStdout() async throws {
        let login = LoginResponse(
            accessToken: "private-access-sentinel", refreshToken: "private-refresh-sentinel",
            expiresIn: 3600, user: UserInfo(id: "user", email: "private-email-sentinel"))
        let data = try JSONEncoder().encode(login)
        SecurityURLProtocol.handler = { request in
            (
                HTTPURLResponse(
                    url: request.url!, statusCode: 200, httpVersion: nil,
                    headerFields: ["Set-Cookie": "session=private-cookie-sentinel"])!, data
            )
        }
        let output = Pipe()
        fflush(stdout)
        let saved = dup(STDOUT_FILENO)
        dup2(output.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)
        defer {
            dup2(saved, STDOUT_FILENO)
            close(saved)
        }
        _ = try await client().authenticateWithPassword(
            email: "private-email-sentinel", password: "private-password-sentinel")
        fflush(stdout)
        dup2(saved, STDOUT_FILENO)
        try output.fileHandleForWriting.close()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        for secret in [
            "private-access-sentinel", "private-refresh-sentinel", "private-email-sentinel",
            "private-cookie-sentinel", "private-password-sentinel",
        ] {
            XCTAssertFalse(text.contains(secret))
        }
    }

    func testPendingLoginExpiresAndCannotBeOverwritten() async throws {
        let c = client()
        let start = Date()
        c.authorizationNow = { start }
        let config = try configuration()
        SecurityURLProtocol.handler = { request in
            XCTAssertTrue(request.url!.path.contains("well-known"), "Expired state must fail before code exchange")
            return self.response(request, config)
        }
        _ = try await c.buildAuthorizationURL(state: "original")
        await assertRejected { _ = try await c.buildAuthorizationURL(state: "replacement") }
        c.authorizationNow = { start.addingTimeInterval(601) }
        await assertRejected { _ = try await c.exchangeCodeForTokens(code: "code", state: "original") }
        _ = try await c.buildAuthorizationURL(state: "fresh")
        try c.clearTokens()
        await assertRejected { _ = try await c.exchangeCodeForTokens(code: "code", state: "fresh") }
    }

    func testHostedSocialRejectsInsecureProviderURL() async throws {
        let config = try configuration()
        for url in ["http://provider.example/auth", "javascript:alert(1)", "https://user:secret@provider.example/auth"]
        {
            SecurityURLProtocol.handler = { request in
                if request.url!.path.contains("well-known") { return self.response(request, config) }
                return self.response(request, try JSONSerialization.data(withJSONObject: ["authorization_url": url]))
            }
            await assertRejected { _ = try await self.client().buildHostedSocialAuthorizationURL(provider: "google") }
        }
    }

    func testRefreshWithoutTokenStoreRetainsVerifiedIdentity() async throws {
        let fixture = try SignedIDTokenFixture()
        let config = try configuration()
        var refreshing = false
        SecurityURLProtocol.handler = { request in
            if request.url!.path.contains("well-known") { return self.response(request, config) }
            if request.url!.path == "/jwks" { return self.response(request, fixture.jwks) }
            var result: [String: Any] = ["access_token": "access", "token_type": "Bearer", "expires_in": 3600]
            if !refreshing { result["id_token"] = try fixture.token() }
            return self.response(request, try JSONSerialization.data(withJSONObject: result))
        }
        let c = OAuth42Client(clientId: "client", redirectURI: "app://callback", issuer: issuer, urlSession: session)
        _ = try await c.buildAuthorizationURL(state: "state", nonce: "nonce")
        let original = try await c.exchangeCodeForTokens(code: "code", state: "state")
        refreshing = true
        let refreshed = try await c.refreshTokens(refreshToken: "refresh")
        XCTAssertEqual(refreshed.idToken, original.idToken)
    }

    static func body(_ request: URLRequest) -> Data {
        if let data = request.httpBody { return data }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count <= 0 { break }
            result.append(contentsOf: buffer.prefix(count))
        }
        return result
    }
}

private final class SecurityURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let (response, data) = try Self.handler!(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}
private final class MemoryStore: TokenStore {
    var tokens: TokenResponse?
    func saveTokens(_ tokens: TokenResponse) throws { self.tokens = tokens }
    func retrieveTokens() throws -> TokenResponse? { tokens }
    func deleteTokens() throws { tokens = nil }
}

struct SignedIDTokenFixture {
    let key: SecKey
    let jwks: Data
    init() throws {
        key = try XCTUnwrap(
            SecKeyCreateRandomKey(
                [
                    kSecAttrKeyType: kSecAttrKeyTypeRSA,
                    kSecAttrKeySizeInBits: 2048,
                ] as CFDictionary, nil))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key))
        let data = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil)) as Data
        // Parse the two INTEGERs in the platform-generated PKCS#1 public key.
        let bytes = [UInt8](data)
        var offset = 1
        func length() -> Int {
            let first = Int(bytes[offset])
            offset += 1
            if first < 128 { return first }
            var value = 0
            for _ in 0..<(first & 127) {
                value = value * 256 + Int(bytes[offset])
                offset += 1
            }
            return value
        }
        _ = length()
        offset += 1
        let nLength = length()
        let n = Data(bytes[offset..<(offset + nLength)].drop(while: { $0 == 0 }))
        offset += nLength + 1
        let eLength = length()
        let e = Data(bytes[offset..<(offset + eLength)])
        jwks = try JSONSerialization.data(withJSONObject: [
            "keys": [
                [
                    "kty": "RSA", "kid": "key", "alg": "RS256", "use": "sig", "n": Self.base64(n),
                    "e": Self.base64(e),
                ]
            ]
        ])
    }
    static func base64(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(
            of: "/", with: "_"
        ).replacingOccurrences(of: "=", with: "")
    }
    func token(_ changes: [String: Any] = [:], header: [String: Any] = [:]) throws -> String {
        var claims: [String: Any] = [
            "iss": "https://issuer.example", "sub": "user", "aud": "client", "nonce": "nonce",
            "iat": Date().timeIntervalSince1970, "exp": Date().timeIntervalSince1970 + 300,
            "at_hash": Self.base64(Data(SHA256.hash(data: Data("access".utf8)).prefix(16))),
        ]
        claims.merge(changes) { _, new in new }
        var headers: [String: Any] = ["alg": "RS256", "kid": "key"]
        headers.merge(header) { _, new in new }
        let input =
            Self.base64(try JSONSerialization.data(withJSONObject: headers)) + "."
            + Self.base64(try JSONSerialization.data(withJSONObject: claims))
        let sig =
            try XCTUnwrap(
                SecKeyCreateSignature(
                    key, .rsaSignatureMessagePKCS1v15SHA256, Data(input.utf8) as CFData, nil)) as Data
        return input + "." + Self.base64(sig)
    }
    func validate(_ claims: [String: Any] = [:], header: [String: Any] = [:], raw: String? = nil)
        throws
    {
        try IDTokenValidator.validate(
            raw ?? token(claims, header: header), jwks: jwks,
            issuer: "https://issuer.example", clientID: "client", nonce: "nonce", accessToken: "access")
    }
}
