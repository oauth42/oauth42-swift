#if os(macOS)
    import XCTest
    import Security
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

    private final class FixtureTrust: NSObject, URLSessionDelegate {
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
