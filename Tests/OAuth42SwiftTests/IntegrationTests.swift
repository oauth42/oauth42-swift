#if os(macOS)
    import XCTest
    import Security
    import CryptoKit
    @testable import OAuth42Swift

    /// Real HTTPS transport tests with a generated local certificate and a disposable server.
    /// No external backend, production credentials, TLS bypass, or conditional skips.
    final class IntegrationTests: XCTestCase {
        func testOIDCDiscoveryAndPKCEOverTrustedTLS() async throws {
            let fixture = try HTTPSFixture()
            defer { fixture.stop() }
            let c = fixture.client()
            let config = try await c.fetchConfiguration()
            XCTAssertEqual(config.issuer, fixture.issuer)
            let url = try await c.buildAuthorizationURL()
            let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
            XCTAssertEqual(query.first { $0.name == "code_challenge_method" }?.value, "S256")
            XCTAssertEqual(query.first { $0.name == "code_challenge" }?.value?.count, 43)
            XCTAssertFalse(query.first { $0.name == "nonce" }?.value?.isEmpty ?? true)
        }

        func testUntrustedCertificateIsRejected() async throws {
            let fixture = try HTTPSFixture()
            defer { fixture.stop() }
            let c = OAuth42Client(
                clientId: "client", redirectURI: "app://callback", issuer: fixture.issuer)
            do {
                _ = try await c.fetchConfiguration()
                XCTFail("Untrusted TLS must fail")
            } catch { XCTAssertTrue(error is URLError) }
        }

        func testTokenRedirectsNeverForwardCredentials() async throws {
            for mode in ["same", "cross"] {
                let fixture = try HTTPSFixture(mode: mode)
                defer { fixture.stop() }
                let c = fixture.client()
                do {
                    _ = try await c.refreshTokens(refreshToken: "sensitive-refresh")
                    XCTFail("Redirect must fail")
                } catch {}
                let (data, _) = try await fixture.session.data(
                    from: URL(string: fixture.issuer + "/stats")!)
                let stats = try JSONSerialization.jsonObject(with: data) as! [String: Int]
                XCTAssertEqual(
                    stats["redirect_hits"], 0, "307 must not transmit credentials to either redirect target")
            }
        }
    }


    /// Explicit local bridge; no Apple CI runner or production account involved.
    final class BackendInteropTests: XCTestCase {
        func testPARCodeRefreshAndPasswordGrantAgainstRealBackend() async throws {
            guard let path = ProcessInfo.processInfo.environment["O42_SWIFT_FIXTURE_DIR"] else {
                throw XCTSkip("Run OAuth42 scripts/test-swift-backend.py on the local Mac")
            }
            let directory = URL(fileURLWithPath:path)
            let values = try JSONSerialization.jsonObject(with:Data(contentsOf:directory.appendingPathComponent("manifest.json"))) as! [String:String]
            let issuer = try XCTUnwrap(values["issuer"])
            let pem = try String(contentsOf:directory.appendingPathComponent("cert.pem"), encoding:.utf8)
            let encoded = pem.components(separatedBy:.newlines).filter{!$0.hasPrefix("---")}.joined()
            let cert = try XCTUnwrap(SecCertificateCreateWithData(nil,Data(base64Encoded:encoded)! as CFData))
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpCookieStorage = nil; configuration.httpShouldSetCookies = false
            let session = URLSession(configuration:configuration,delegate:FixtureTrust(cert),delegateQueue:nil)
            defer { session.invalidateAndCancel() }
            let signing = P256.Signing.PrivateKey()
            let key = DPoPKey(publicKey:signing.publicKey,hardware:false){ try signing.signature(for:$0).rawRepresentation }
            let store = BackendTokenStore()
            let client = OAuth42Client(clientId:"oauth42-public",redirectURI:"o42test://callback",issuer:issuer,tokenStore:store,urlSession:session,dpopKey:key)
            // Password login must retain its distinct refresh route after persistence.
            _ = try await client.authenticateWithPassword(email:values["email"]!,password:values["password"]!)
            let passwordRefresh = try await client.refreshTokens()
            XCTAssertEqual(passwordRefresh.tokenType,"DPoP")
            XCTAssertEqual(passwordRefresh.refreshGrant,"auth_login")
            try client.clearTokens()
            // The authorization driver is a synthetic already-authenticated browser.
            var login = URLRequest(url:URL(string:issuer + "/auth/login")!)
            login.httpMethod="POST"; login.setValue("application/json",forHTTPHeaderField:"Content-Type")
            login.httpBody=try JSONSerialization.data(withJSONObject:["email":values["email"]!,"password":values["password"]!])
            let (data,response)=try await session.data(for:login)
            XCTAssertEqual((response as! HTTPURLResponse).statusCode,200)
            let access=(try JSONSerialization.jsonObject(with:data) as! [String:Any])["access_token"] as! String
            var identityRequest = URLRequest(url:URL(string:issuer + "/users/me")!)
            identityRequest.setValue("Bearer \(access)",forHTTPHeaderField:"Authorization")
            let (_,identityResponse) = try await session.data(for:identityRequest)
            XCTAssertEqual((identityResponse as! HTTPURLResponse).statusCode,200)
            let authorization = try await client.buildAuthorizationURL(state:"swift-backend-state",nonce:"swift-backend-nonce",pushedAuthorization:true)
            XCTAssertEqual(Set(URLComponents(url:authorization,resolvingAgainstBaseURL:false)!.queryItems!.map(\.name)),Set(["client_id","request_uri"]))
            var request=URLRequest(url:authorization);request.setValue("Bearer \(access)",forHTTPHeaderField:"Authorization")
            let (_,start)=try await session.data(for:request)
            XCTAssertEqual((start as! HTTPURLResponse).statusCode,302)
            let next=try XCTUnwrap((start as! HTTPURLResponse).value(forHTTPHeaderField:"Location"))
            request.url=URL(string:next,relativeTo:URL(string:issuer)!)!
            let (_,redirect)=try await session.data(for:request)
            XCTAssertEqual((redirect as! HTTPURLResponse).statusCode,302)
            let location=try XCTUnwrap((redirect as! HTTPURLResponse).value(forHTTPHeaderField:"Location"))
            let callback=try XCTUnwrap(URLComponents(string:location))
            XCTAssertEqual(callback.scheme,"o42test")
            let query=Dictionary(uniqueKeysWithValues:callback.queryItems!.map{($0.name,$0.value ?? "")})
            let tokens=try await client.exchangeCodeForTokens(code:XCTUnwrap(query["code"]),state:XCTUnwrap(query["state"]))
            XCTAssertEqual(tokens.tokenType,"DPoP")
            let user=try await client.fetchUserInfo();XCTAssertEqual(user.email,values["email"])
            let refreshed=try await client.refreshTokens()
            XCTAssertNotEqual(tokens.refreshToken,refreshed.refreshToken)
            XCTAssertEqual(refreshed.tokenType,"DPoP")
            let refreshedUser = try await client.fetchUserInfo()
            XCTAssertEqual(refreshedUser.id,user.id)
            let wrong=P256.Signing.PrivateKey()
            let other=DPoPKey(publicKey:wrong.publicKey,hardware:false){try wrong.signature(for:$0).rawRepresentation}
            let impostor=OAuth42Client(clientId:"oauth42-public",redirectURI:"o42test://callback",issuer:issuer,urlSession:session,dpopKey:other)
            do { _ = try await impostor.refreshTokens(refreshToken:refreshed.refreshToken);XCTFail("Stolen refresh accepted without original key") } catch {}
            // Failed theft must not revoke the legitimate holder's refresh grant.
            _ = try await client.refreshTokens()
        }
    }
    private final class BackendTokenStore: TokenStore {
        private var saved: Data?
        func saveTokens(_ tokens:TokenResponse) throws { saved=try JSONEncoder().encode(tokens) }
        func retrieveTokens() throws -> TokenResponse? { try saved.map { try JSONDecoder().decode(TokenResponse.self,from:$0) } }
        func deleteTokens() throws { saved=nil }
    }

    private final class HTTPSFixture {
        let directory: URL
        let process: Process
        let input = Pipe()
        let issuer: String
        let session: URLSession
        init(mode: String = "cross") throws {
            directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let cert = directory.appendingPathComponent("cert.pem").path
            let key = directory.appendingPathComponent("key.pem").path
            let openssl = Process()
            openssl.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            openssl.arguments = [
                "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1", "-keyout", key,
                "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                "-addext", "extendedKeyUsage=serverAuth",
            ]
            openssl.standardOutput = FileHandle.nullDevice
            openssl.standardError = FileHandle.nullDevice
            try openssl.run()
            openssl.waitUntilExit()
            guard openssl.terminationStatus == 0 else { throw URLError(.cannotCreateFile) }
            let pem = try String(contentsOfFile: cert)
            let base64 = pem.components(separatedBy: .newlines).filter { !$0.hasPrefix("---") }.joined()
            let certificate = try XCTUnwrap(
                SecCertificateCreateWithData(nil, Data(base64Encoded: base64)! as CFData))
            session = URLSession(
                configuration: .ephemeral, delegate: FixtureTrust(certificate), delegateQueue: nil)
            process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            let script = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
                .appendingPathComponent("Fixtures/https_server.py").path
            process.arguments = ["python3", "-u", script, cert, key, mode]
            let output = Pipe()
            process.standardOutput = output
            process.standardInput = input
            process.standardError = FileHandle.nullDevice
            try process.run()
            var line = Data()
            while let byte = try output.fileHandleForReading.read(upToCount: 1), !byte.isEmpty,
                byte != Data([10])
            { line.append(byte) }
            guard let port = Int(String(decoding: line, as: UTF8.self)) else {
                throw URLError(.cannotConnectToHost)
            }
            issuer = "https://localhost:\(port)"
        }
        func client() -> OAuth42Client {
            OAuth42Client(
                clientId: "client", redirectURI: "app://callback", issuer: issuer, urlSession: session)
        }
        func stop() {
            try? input.fileHandleForWriting.close()
            if process.isRunning { process.terminate() }
            session.invalidateAndCancel()
            try? FileManager.default.removeItem(at: directory)
        }
    }

    private final class FixtureTrust: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
        let certificate: SecCertificate
        init(_ certificate: SecCertificate) { self.certificate = certificate }
        func urlSession(
            _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                challenge.protectionSpace.host == "localhost",
                let trust = challenge.protectionSpace.serverTrust
            else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            SecTrustSetAnchorCertificates(trust, [certificate] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var trustError: CFError?
            if SecTrustEvaluateWithError(trust, &trustError) {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                print("Fixture trust error: \(String(describing: trustError))")
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
    }
#endif
