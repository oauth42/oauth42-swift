import CryptoKit
import XCTest
@testable import OAuth42Swift

final class DPoPTests: XCTestCase {
    private func key() -> (DPoPKey, P256.Signing.PublicKey) {
        let key = P256.Signing.PrivateKey()
        return (DPoPKey(publicKey: key.publicKey, hardware: false) { try key.signature(for: $0).rawRepresentation }, key.publicKey)
    }
    private func decode(_ value: Substring) throws -> Data {
        var base64 = String(value).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return try XCTUnwrap(Data(base64Encoded: base64))
    }
    private func verify(_ proof: String, _ publicKey: P256.Signing.PublicKey) throws -> [String: Any] {
        let parts = proof.split(separator: ".")
        XCTAssertEqual(parts.count, 3)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: decode(parts[2]))
        XCTAssertTrue(publicKey.isValidSignature(signature, for: Data("\(parts[0]).\(parts[1])".utf8)))
        let header = try JSONSerialization.jsonObject(with: decode(parts[0])) as! [String: Any]
        XCTAssertEqual(header["typ"] as? String, "dpop+jwt")
        XCTAssertNil((header["jwk"] as? [String: String])?["d"])
        return try JSONSerialization.jsonObject(with: decode(parts[1])) as! [String: Any]
    }
    func testKeychainLifecycleDoesNotReplaceAnExistingKey() throws {
        let store = DPoPKeyStore(service: "com.oauth42.tests.dpop." + UUID().uuidString)
        defer { try? store.delete() }
        XCTAssertNil(try store.load())
        let first = try store.create(allowSoftwareFallback: true)
        XCTAssertEqual(try store.load()?.thumbprint, first.thumbprint)
        XCTAssertThrowsError(try store.create(allowSoftwareFallback: true))
        XCTAssertEqual(try store.load()?.thumbprint, first.thumbprint)
        try store.delete()
        XCTAssertNil(try store.load())
        let replacement = try store.create(allowSoftwareFallback: true)
        XCTAssertNotEqual(replacement.thumbprint, first.thumbprint)
    }
    func testProofBindsRequestAndAccessTokenWithFreshID() throws {
        let (key, publicKey) = key()
        let url = URL(string: "https://issuer.example/resource?query=omitted#fragment")!
        let first = try verify(key.proof(method: "GET", url: url, nonce: "nonce", accessToken: "access"), publicKey)
        let second = try verify(key.proof(method: "GET", url: url), publicKey)
        XCTAssertEqual(first["htu"] as? String, "https://issuer.example/resource")
        XCTAssertEqual(first["htm"] as? String, "GET")
        XCTAssertEqual(first["nonce"] as? String, "nonce")
        XCTAssertEqual(first["ath"] as? String, DPoPKey.base64(Data(SHA256.hash(data: Data("access".utf8)))))
        XCTAssertNotEqual(first["jti"] as? String, second["jti"] as? String)
        XCTAssertEqual(key.thumbprint.count, 43)
        XCTAssertThrowsError(try key.proof(method: "GET", url: URL(string: "http://issuer.example")!))
        XCTAssertThrowsError(try key.proof(method: "GET", url: URL(string: "https://user:pass@issuer.example")!))
    }
    func testNonceRetryAndDowngradeRejection() async throws {
        let (key, publicKey) = key()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [DPoPProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel(); DPoPProtocol.handler = nil }
        let store = DPoPMemoryStore()
        let client = OAuth42Client(clientId: "native", redirectURI: "app://callback", issuer: "https://issuer.example", scopes: ["email"], tokenStore: store, urlSession: session, dpopKey: key)
        var calls = 0
        var ids: [String] = []
        var downgrade = false
        DPoPProtocol.handler = { request in
            var status = 200; var headers: [String: String] = [:]; let body: [String: Any]
            if request.url!.path.contains("well-known") {
                XCTAssertNil(request.value(forHTTPHeaderField: "DPoP"))
                body = ["issuer":"https://issuer.example", "authorization_endpoint":"https://issuer.example/authorize", "token_endpoint":"https://issuer.example/token", "jwks_uri":"https://issuer.example/jwks", "response_types_supported":["code"], "subject_types_supported":["public"], "id_token_signing_alg_values_supported":["RS256"]]
            } else {
                calls += 1
                let proof = try self.verify(XCTUnwrap(request.value(forHTTPHeaderField: "DPoP")), publicKey)
                ids.append(proof["jti"] as! String)
                XCTAssertEqual(proof["htm"] as? String, "POST")
                if calls == 1 {
                    status = 400; headers["DPoP-Nonce"] = "server-nonce"
                    body = ["error":"use_dpop_nonce"]
                } else {
                    XCTAssertEqual(proof["nonce"] as? String, "server-nonce")
                    body = ["access_token":"access", "refresh_token":"refresh2", "token_type": downgrade ? "Bearer" : "DPoP", "expires_in":900]
                }
            }
            return (HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: headers)!, try JSONSerialization.data(withJSONObject: body))
        }
        let tokens = try await client.refreshTokens(refreshToken: "refresh")
        XCTAssertEqual(tokens.tokenType, "DPoP")
        XCTAssertEqual(calls, 2)
        XCTAssertEqual(Set(ids).count, 2)
        XCTAssertEqual(try client.getStoredTokens()?.dpopKeyThumbprint, key.thumbprint)
        downgrade = true
        do { _ = try await client.refreshTokens(); XCTFail("Bearer downgrade accepted") } catch {}
        let wrongKeyClient = OAuth42Client(clientId: "native", redirectURI: "app://callback", issuer: "https://issuer.example", tokenStore: store, urlSession: session, dpopKey: self.key().0)
        XCTAssertThrowsError(try wrongKeyClient.getStoredTokens())
        let noKeyClient = OAuth42Client(clientId: "native", redirectURI: "app://callback", issuer: "https://issuer.example", tokenStore: store)
        XCTAssertThrowsError(try noKeyClient.getStoredTokens())
        try client.clearTokens()
        XCTAssertNil(try client.getStoredTokens())
    }
    func testPARUsesOpaqueReferenceAndKeepsPKCEAndNonceOnServer() async throws {
        let (key, publicKey) = key()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [DPoPProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel(); DPoPProtocol.handler = nil }
        let client = OAuth42Client(clientId: "native", redirectURI: "app://callback", issuer: "https://issuer.example", tokenStore: DPoPMemoryStore(), urlSession: session, dpopKey: key)
        var calls = 0
        var rejected = false
        DPoPProtocol.handler = { request in
            let body: [String: Any]; let status: Int
            if request.url!.path.contains("well-known") {
                status = 200
                body = ["issuer":"https://issuer.example", "authorization_endpoint":"https://issuer.example/authorize", "token_endpoint":"https://issuer.example/token", "jwks_uri":"https://issuer.example/jwks", "response_types_supported":["code"], "subject_types_supported":["public"], "id_token_signing_alg_values_supported":["RS256"], "pushed_authorization_request_endpoint":"https://issuer.example/par", "require_pushed_authorization_requests":true]
            } else {
                XCTAssertEqual(request.url!.path, "/par")
                _ = try self.verify(XCTUnwrap(request.value(forHTTPHeaderField: "DPoP")), publicKey)
                calls += 1
                status = rejected ? 500 : 201
                body = ["request_uri":"urn:ietf:params:oauth:request_uri:" + String(repeating:"a", count:43), "expires_in":300]
            }
            return (HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!, try JSONSerialization.data(withJSONObject: body))
        }
        let url = try await client.buildAuthorizationURL(state: "private-state", nonce: "private-nonce")
        let items = URLComponents(url:url, resolvingAgainstBaseURL:false)!.queryItems!
        XCTAssertEqual(Set(items.map(\.name)), Set(["client_id", "request_uri"]))
        XCTAssertFalse(url.absoluteString.contains("private-state"))
        XCTAssertEqual(calls, 1)
        try client.clearTokens()
        rejected = true
        do { _ = try await client.buildAuthorizationURL(state:"failed"); XCTFail("PAR failure downgraded to redirect") } catch {}
        rejected = false
        _ = try await client.buildAuthorizationURL(state:"fresh")
        XCTAssertEqual(calls, 3)
    }

    func testPasswordRefreshRetainsGrantAndRejectsBearerDowngrade() async throws {
        let (key, publicKey) = key()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [DPoPProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel(); DPoPProtocol.handler = nil }
        let store = DPoPMemoryStore()
        let client = OAuth42Client(clientId:"native", redirectURI:"app://callback", issuer:"https://issuer.example", tokenStore:store, urlSession:session, dpopKey:key)
        var paths: [String] = []
        var downgrade = false
        DPoPProtocol.handler = { request in
            paths.append(request.url!.path)
            _ = try self.verify(XCTUnwrap(request.value(forHTTPHeaderField:"DPoP")), publicKey)
            var body: [String:Any] = ["access_token":"access", "refresh_token":"opaque", "token_type":downgrade ? "Bearer" : "DPoP", "expires_in":900]
            if request.url!.path == "/auth/login" { body["user"] = ["sub":"user", "email":"user@example.com"] }
            else { XCTAssertEqual(request.url!.path,"/auth/refresh"); XCTAssertEqual(request.value(forHTTPHeaderField:"Authorization"), "DPoP opaque") }
            return (HTTPURLResponse(url:request.url!, statusCode:200, httpVersion:nil, headerFields:nil)!, try JSONSerialization.data(withJSONObject:body))
        }
        _ = try await client.authenticateWithPassword(email:"user@example.com", password:"fixture")
        XCTAssertEqual(try client.getStoredTokens()?.refreshGrant,"auth_login")
        // Keychain serializes local grant metadata; it must survive a client restart.
        store.tokens = try JSONDecoder().decode(TokenResponse.self, from:JSONEncoder().encode(XCTUnwrap(store.tokens)))
        _ = try await client.refreshTokens()
        XCTAssertEqual(paths, ["/auth/login", "/auth/refresh"])
        XCTAssertEqual(try client.getStoredTokens()?.dpopKeyThumbprint, key.thumbprint)
        downgrade = true
        do { _ = try await client.refreshTokens(); XCTFail("Bearer password-refresh downgrade accepted") } catch {}
    }

}
private final class DPoPMemoryStore: TokenStore {
    var tokens: TokenResponse?
    func saveTokens(_ tokens: TokenResponse) throws { self.tokens = tokens }
    func retrieveTokens() throws -> TokenResponse? { tokens }
    func deleteTokens() throws { tokens = nil }
}
private final class DPoPProtocol: URLProtocol {
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
