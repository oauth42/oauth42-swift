import Foundation

/// Main OAuth42 client for handling authentication flows
public class OAuth42Client {
    private let clientId: String
    private let clientSecret: String?
    private let redirectURI: String
    private let issuer: String
    private let scopes: [String]
    private let tokenStore: TokenStore?
    private let urlSession: URLSession

    private var configuration: OIDCConfiguration?
    private var currentPKCE: PKCEManager.PKCEPair?
    private var currentState: String?

    /// Initialize OAuth42Client
    /// - Parameters:
    ///   - clientId: OAuth2 client ID
    ///   - clientSecret: Optional client secret (for confidential clients)
    ///   - redirectURI: OAuth2 redirect URI (e.g., "myapp://oauth-callback")
    ///   - issuer: OAuth42 issuer URL (e.g., "https://localhost:8443")
    ///   - scopes: Requested scopes (default: ["openid", "profile", "email"])
    ///   - tokenStore: Optional token store for persistence
    ///   - urlSession: Optional custom URLSession
    public init(
        clientId: String,
        clientSecret: String? = nil,
        redirectURI: String,
        issuer: String,
        scopes: [String] = ["openid", "profile", "email"],
        tokenStore: TokenStore? = nil,
        urlSession: URLSession = .shared
    ) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.issuer = issuer
        self.scopes = scopes
        self.tokenStore = tokenStore
        self.urlSession = urlSession
    }

    // MARK: - OIDC Discovery

    /// Fetch OIDC configuration from well-known endpoint
    public func fetchConfiguration() async throws -> OIDCConfiguration {
        if let cached = configuration {
            return cached
        }

        let discoveryURL = issuer.appending("/.well-known/openid-configuration")
        guard let url = URL(string: discoveryURL) else {
            throw OAuth42Error.invalidURL(discoveryURL)
        }

        let (data, response) = try await urlSession.data(from: url)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        guard httpResponse.statusCode == 200 else {
            throw OAuth42Error.invalidResponse("HTTP \(httpResponse.statusCode)")
        }

        let decoder = JSONDecoder()
        let config = try decoder.decode(OIDCConfiguration.self, from: data)
        self.configuration = config
        return config
    }

    // MARK: - Authorization

    /// Build authorization URL for starting OAuth2 flow
    /// - Parameter state: Optional state parameter for CSRF protection
    /// - Returns: Authorization URL to open in browser
    public func buildAuthorizationURL(state: String? = nil) async throws -> URL {
        let config = try await fetchConfiguration()

        // Generate PKCE parameters
        let pkce = try PKCEManager.generatePKCEPair()
        self.currentPKCE = pkce

        // Generate or use provided state
        let stateValue = state ?? UUID().uuidString
        self.currentState = stateValue

        // Build query parameters
        var components = URLComponents(string: config.authorizationEndpoint)
        components?.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "scope", value: scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: stateValue),
            URLQueryItem(name: "code_challenge", value: pkce.codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: pkce.codeChallengeMethod)
        ]

        guard let url = components?.url else {
            throw OAuth42Error.invalidURL("Failed to build authorization URL")
        }

        return url
    }

    // MARK: - Token Exchange

    /// Exchange authorization code for tokens
    /// - Parameters:
    ///   - code: Authorization code from redirect
    ///   - state: State parameter from redirect (for CSRF validation)
    /// - Returns: Token response with access_token, refresh_token, etc.
    public func exchangeCodeForTokens(code: String, state: String) async throws -> TokenResponse {
        // Validate state to prevent CSRF
        guard state == currentState else {
            throw OAuth42Error.invalidState
        }

        guard let pkce = currentPKCE else {
            throw OAuth42Error.tokenExchangeFailed("Missing PKCE verifier")
        }

        let config = try await fetchConfiguration()

        guard let url = URL(string: config.tokenEndpoint) else {
            throw OAuth42Error.invalidURL(config.tokenEndpoint)
        }

        // Build form parameters
        var parameters: [String: String] = [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirectURI,
            "client_id": clientId,
            "code_verifier": pkce.codeVerifier
        ]

        if let clientSecret = clientSecret {
            parameters["client_secret"] = clientSecret
        }

        let tokens = try await performTokenRequest(url: url, parameters: parameters)

        // Store tokens if token store is configured
        if let tokenStore = tokenStore {
            try tokenStore.saveTokens(tokens)
        }

        // Clear PKCE and state after successful exchange
        self.currentPKCE = nil
        self.currentState = nil

        return tokens
    }

    // MARK: - Token Refresh

    /// Refresh access token using refresh token
    /// - Parameter refreshToken: The refresh token (optional, will use stored token if nil)
    /// - Returns: New token response
    public func refreshTokens(refreshToken: String? = nil) async throws -> TokenResponse {
        let refreshTokenValue: String

        if let provided = refreshToken {
            refreshTokenValue = provided
        } else if let stored = try tokenStore?.retrieveTokens()?.refreshToken {
            refreshTokenValue = stored
        } else {
            throw OAuth42Error.missingRefreshToken
        }

        let config = try await fetchConfiguration()

        guard let url = URL(string: config.tokenEndpoint) else {
            throw OAuth42Error.invalidURL(config.tokenEndpoint)
        }

        var parameters: [String: String] = [
            "grant_type": "refresh_token",
            "refresh_token": refreshTokenValue,
            "client_id": clientId
        ]

        if let clientSecret = clientSecret {
            parameters["client_secret"] = clientSecret
        }

        let tokens = try await performTokenRequest(url: url, parameters: parameters)

        // Store refreshed tokens
        if let tokenStore = tokenStore {
            try tokenStore.saveTokens(tokens)
        }

        return tokens
    }

    // MARK: - User Info

    /// Fetch user information using access token
    /// Automatically refreshes the token if it's expired.
    /// - Parameter accessToken: The access token (optional, will use stored token and auto-refresh if nil)
    /// - Returns: User information
    public func fetchUserInfo(accessToken: String? = nil) async throws -> UserInfo {
        let accessTokenValue: String

        if let provided = accessToken {
            // Use provided token as-is (caller's responsibility to ensure it's valid)
            accessTokenValue = provided
        } else {
            // Automatically get valid token, refreshing if necessary
            accessTokenValue = try await getValidAccessToken()
        }

        let config = try await fetchConfiguration()

        guard let userinfoEndpoint = config.userinfoEndpoint,
              let url = URL(string: userinfoEndpoint) else {
            throw OAuth42Error.invalidConfiguration("No userinfo endpoint in configuration")
        }

        var request = URLRequest(url: url)
        request.setValue("Bearer \(accessTokenValue)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await urlSession.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        guard httpResponse.statusCode == 200 else {
            throw OAuth42Error.invalidResponse("HTTP \(httpResponse.statusCode)")
        }

        let decoder = JSONDecoder()
        return try decoder.decode(UserInfo.self, from: data)
    }

    // MARK: - Token Management

    /// Get stored tokens if available
    public func getStoredTokens() throws -> TokenResponse? {
        return try tokenStore?.retrieveTokens()
    }

    /// Clear stored tokens
    public func clearTokens() throws {
        try tokenStore?.deleteTokens()
    }

    /// Get valid access token, refreshing if necessary
    /// This method automatically refreshes the token if it's expired (within 60 second threshold).
    /// - Returns: A valid access token
    public func getValidAccessToken() async throws -> String {
        guard let tokens = try getStoredTokens() else {
            throw OAuth42Error.authorizationFailed("No stored tokens")
        }

        // If token is not expired, return it
        if !tokens.isExpired() {
            return tokens.accessToken
        }

        // Token is expired, try to refresh
        let refreshedTokens = try await refreshTokens(refreshToken: tokens.refreshToken)
        return refreshedTokens.accessToken
    }

    /// Make an authenticated API request with automatic token refresh
    /// Convenience method for making custom API calls with automatic token management.
    /// - Parameters:
    ///   - url: The URL to request
    ///   - method: HTTP method (default: GET)
    ///   - body: Optional request body data
    /// - Returns: Response data and HTTP response
    public func makeAuthenticatedRequest(
        url: URL,
        method: String = "GET",
        body: Data? = nil
    ) async throws -> (Data, HTTPURLResponse) {
        let accessToken = try await getValidAccessToken()

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let body = body {
            request.httpBody = body
        }

        let (data, response) = try await urlSession.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        return (data, httpResponse)
    }

    // MARK: - Private Helpers

    private func performTokenRequest(url: URL, parameters: [String: String]) async throws -> TokenResponse {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        // Build form body
        let formBody = parameters
            .map { key, value in
                let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key
                let encodedValue = value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
                return "\(encodedKey)=\(encodedValue)"
            }
            .joined(separator: "&")

        request.httpBody = formBody.data(using: .utf8)

        let (data, response) = try await urlSession.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        // Check for error response
        if httpResponse.statusCode != 200 {
            if let errorResponse = try? JSONDecoder().decode(OAuth2ErrorResponse.self, from: data) {
                throw OAuth42Error.tokenExchangeFailed("\(errorResponse.error): \(errorResponse.errorDescription ?? "Unknown error")")
            }
            throw OAuth42Error.tokenExchangeFailed("HTTP \(httpResponse.statusCode)")
        }

        // Decode success response
        let decoder = JSONDecoder()
        var tokenResponse = try decoder.decode(TokenResponse.self, from: data)

        // Ensure receivedAt is set to current time
        tokenResponse = TokenResponse(
            accessToken: tokenResponse.accessToken,
            tokenType: tokenResponse.tokenType,
            expiresIn: tokenResponse.expiresIn,
            refreshToken: tokenResponse.refreshToken,
            scope: tokenResponse.scope,
            idToken: tokenResponse.idToken,
            receivedAt: Date()
        )

        return tokenResponse
    }
}
