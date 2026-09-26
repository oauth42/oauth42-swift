import Foundation

// Never forward credentials through an HTTP redirect, including same-origin redirects.
final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

enum SecurityPolicy {
    static func httpsURL(_ value: String) throws -> URL {
        guard let url = URL(string: value), url.scheme?.lowercased() == "https",
            let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
            url.fragment == nil
        else {
            throw OAuth42Error.invalidURL("A credential-free HTTPS URL is required")
        }
        return url
    }

    static func origin(_ url: URL) -> String {
        "\(url.scheme?.lowercased() ?? "")://\(url.host?.lowercased() ?? ""):\(url.port ?? 443)"
    }

    static func endpoint(_ value: String, issuer: String) throws -> URL {
        let url = try httpsURL(value)
        guard origin(url) == origin(try httpsURL(issuer)) else {
            throw OAuth42Error.invalidConfiguration("Endpoint is outside the configured issuer origin")
        }
        return url
    }

    static func validate(_ tokens: TokenResponse) throws {
        guard !tokens.accessToken.isEmpty, tokens.tokenType.lowercased() == "bearer",
            tokens.expiresIn > 0, tokens.refreshToken?.isEmpty != true,
            !tokens.accessToken.contains(where: { $0.isWhitespace || $0.isNewline })
        else {
            throw OAuth42Error.invalidResponse("Invalid bearer token response")
        }
    }
}
