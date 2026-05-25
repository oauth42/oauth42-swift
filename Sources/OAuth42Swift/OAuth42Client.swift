import Foundation

/// Main OAuth42 client for handling authentication flows
public class OAuth42Client {
    private let clientId: String
    private let clientSecret: String?
    private let redirectURI: String
    private let issuer: String
    private let hostedAuthBaseURL: String
    private let scopes: [String]
    private let tokenStore: TokenStore?
    private let urlSession: URLSession

    /// Optional URL transformer for translating URLs (e.g., localhost to IP for iOS device testing)
    private let urlTransformer: ((String) -> String)?

    private var configuration: OIDCConfiguration?
    private var currentPKCE: PKCEManager.PKCEPair?
    private var currentState: String?

    /// Initialize OAuth42Client
    /// - Parameters:
    ///   - clientId: OAuth2 client ID
    ///   - clientSecret: Optional client secret (for confidential clients)
    ///   - redirectURI: OAuth2 redirect URI (e.g., "myapp://oauth-callback")
    ///   - issuer: OAuth42 OIDC issuer URL (e.g., "https://api.oauth42.com")
    ///   - hostedAuthBaseURL: OAuth42 hosted auth URL for social sign-in (e.g., "https://auth.oauth42.com")
    ///   - scopes: Requested scopes (default: ["openid", "profile", "email"])
    ///   - tokenStore: Optional token store for persistence
    ///   - urlSession: Optional custom URLSession
    ///   - urlTransformer: Optional URL transformer for translating URLs (e.g., localhost to IP)
    public init(
        clientId: String,
        clientSecret: String? = nil,
        redirectURI: String,
        issuer: String,
        hostedAuthBaseURL: String? = nil,
        scopes: [String] = ["openid", "profile", "email"],
        tokenStore: TokenStore? = nil,
        urlSession: URLSession = .shared,
        urlTransformer: ((String) -> String)? = nil
    ) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.issuer = OAuth42Client.normalizedBaseURL(issuer)
        self.hostedAuthBaseURL = hostedAuthBaseURL.map(OAuth42Client.normalizedBaseURL)
            ?? OAuth42Client.defaultHostedAuthBaseURL(for: issuer)
        self.scopes = scopes
        self.tokenStore = tokenStore
        self.urlSession = urlSession
        self.urlTransformer = urlTransformer
    }

    // MARK: - URL Transformation

    /// Transform a URL string using the configured transformer
    /// This is used to convert localhost URLs to IP addresses for iOS device testing
    private func transformURL(_ urlString: String) -> String {
        if let transformer = urlTransformer {
            return transformer(urlString)
        }
        return urlString
    }

    private static func normalizedBaseURL(_ urlString: String) -> String {
        return urlString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    private static func defaultHostedAuthBaseURL(for issuer: String) -> String {
        let normalizedIssuer = normalizedBaseURL(issuer)
        guard var components = URLComponents(string: normalizedIssuer),
              let host = components.host else {
            return normalizedIssuer
        }

        if host == "api.oauth42.com" {
            components.host = "auth.oauth42.com"
            return components.string ?? "https://auth.oauth42.com"
        }

        if host.hasPrefix("api.") {
            components.host = "auth." + host.dropFirst(4)
            return components.string ?? normalizedIssuer
        }

        return normalizedIssuer
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
            if httpResponse.statusCode == 404 {
                throw OAuth42Error.invalidIssuer(
                    "OIDC discovery was not found at \(discoveryURL). Use the canonical OAuth42 issuer, such as https://api.oauth42.com, and configure hostedAuthBaseURL separately for hosted social sign-in."
                )
            }
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

        // Build query parameters (transform URL for local development)
        var components = URLComponents(string: transformURL(config.authorizationEndpoint))
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

    // MARK: - Hosted Social Authentication

    /// Fetch hosted social providers enabled for this OAuth client.
    /// - Returns: Provider identifiers such as `google`, `github`, or `apple`.
    public func fetchHostedSocialProviders() async throws -> [String] {
        _ = try await fetchConfiguration()

        guard var components = URLComponents(
            string: hostedAuthBaseURL.appending("/api/social-providers")
        ) else {
            throw OAuth42Error.invalidURL(hostedAuthBaseURL)
        }
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId)
        ]

        guard let providerURL = components.url else {
            throw OAuth42Error.invalidURL("Failed to build hosted social providers URL")
        }
        guard let url = URL(string: transformURL(providerURL.absoluteString)) else {
            throw OAuth42Error.invalidURL(providerURL.absoluteString)
        }

        let (data, response) = try await urlSession.data(from: url)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        guard (200..<300).contains(httpResponse.statusCode) else {
            throw hostedSocialError(
                statusCode: httpResponse.statusCode,
                data: data,
                fallback: "Could not fetch hosted social providers from \(url.absoluteString)"
            )
        }

        let providerResponse = try JSONDecoder().decode(HostedSocialProvidersResponse.self, from: data)
        return normalizedProviders(providerResponse.providers)
    }

    /// Build a provider authorization URL for OAuth42 hosted social sign-in.
    /// - Parameters:
    ///   - provider: Social provider identifier such as `google`, `github`, or `apple`.
    ///   - isSignup: Whether the hosted flow should be treated as signup.
    ///   - state: Optional state parameter for CSRF protection.
    /// - Returns: Provider authorization URL to open in a browser or ASWebAuthenticationSession.
    public func buildHostedSocialAuthorizationURL(
        provider: String,
        isSignup: Bool = false,
        state: String? = nil
    ) async throws -> URL {
        _ = try await fetchConfiguration()

        guard let url = URL(string: transformURL(hostedAuthBaseURL.appending("/api/social-auth/init"))) else {
            throw OAuth42Error.invalidURL(hostedAuthBaseURL)
        }

        let pkce = try PKCEManager.generatePKCEPair()
        let stateValue = state ?? UUID().uuidString
        self.currentPKCE = pkce
        self.currentState = stateValue

        let payload = HostedSocialAuthInitRequest(
            provider: provider.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            clientId: clientId,
            redirectURI: redirectURI,
            state: stateValue,
            isSignup: isSignup
        )

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONEncoder().encode(payload)

        do {
            let (data, response) = try await urlSession.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                throw OAuth42Error.invalidResponse("Not an HTTP response")
            }

            guard (200..<300).contains(httpResponse.statusCode) else {
                throw hostedSocialError(
                    statusCode: httpResponse.statusCode,
                    data: data,
                    fallback: "Could not start hosted social sign-in for provider \(provider)"
                )
            }

            let providerResponse = try JSONDecoder().decode(HostedSocialAuthInitResponse.self, from: data)
            guard let authorizationURL = URL(string: providerResponse.authorizationURL) else {
                throw OAuth42Error.hostedSocialAuthFailed("Invalid authorization_url in hosted social response")
            }

            return authorizationURL
        } catch {
            self.currentPKCE = nil
            self.currentState = nil
            throw error
        }
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

        // Transform the URL for local development (e.g., localhost -> IP)
        let transformedEndpoint = transformURL(config.tokenEndpoint)
        guard let url = URL(string: transformedEndpoint) else {
            throw OAuth42Error.invalidURL(transformedEndpoint)
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

        // Transform the URL for local development (e.g., localhost -> IP)
        let transformedEndpoint = transformURL(config.tokenEndpoint)
        guard let url = URL(string: transformedEndpoint) else {
            throw OAuth42Error.invalidURL(transformedEndpoint)
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

    // MARK: - Password Authentication (First-Party Apps Only)

    /// Authenticate with username and password (for first-party apps like authenticator)
    /// ⚠️ WARNING: Only use this for first-party OAuth42 apps (like the authenticator app).
    /// Third-party apps should use the browser-based authorization code flow.
    /// - Parameters:
    ///   - email: User's email address
    ///   - password: User's password
    ///   - mfaCode: Optional MFA code (6 digits) if MFA is enabled
    ///   - rememberMe: Whether to request a refresh token
    /// - Returns: Login response with tokens and user info
    /// - Throws: OAuth42Error.mfaRequired if MFA is enabled and no code provided
    public func authenticateWithPassword(
        email: String,
        password: String,
        mfaCode: String? = nil,
        rememberMe: Bool = true
    ) async throws -> LoginResponse {
        // Build login endpoint URL
        // The login endpoint is typically at /auth/login or /login
        let loginEndpoint = issuer.appending("/auth/login")
        guard let url = URL(string: loginEndpoint) else {
            throw OAuth42Error.invalidURL(loginEndpoint)
        }

        // Create login request
        let loginRequest = LoginRequest(
            email: email,
            password: password,
            mfaCode: mfaCode,
            rememberMe: rememberMe
        )

        // Perform login request
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        request.httpBody = try encoder.encode(loginRequest)

        let (data, response) = try await urlSession.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        // Debug logging
        print("🔍 [OAuth42Client] Response status: \(httpResponse.statusCode)")
        print("🔍 [OAuth42Client] Response headers: \(httpResponse.allHeaderFields)")
        if let responseString = String(data: data, encoding: .utf8) {
            print("🔍 [OAuth42Client] Response body: \(responseString)")
        } else {
            print("❌ [OAuth42Client] Could not decode response body as UTF-8")
        }

        // Handle different response codes
        switch httpResponse.statusCode {
        case 200:
            // Success - decode login response
            let decoder = JSONDecoder()
            // NOTE: Don't use .convertFromSnakeCase here because LoginResponse and UserInfo
            // already have explicit CodingKeys that handle snake_case mapping
            decoder.dateDecodingStrategy = .iso8601

            print("🔍 [OAuth42Client] Attempting to decode LoginResponse...")
            var loginResponse = try decoder.decode(LoginResponse.self, from: data)

            // Ensure receivedAt is set to current time
            loginResponse = LoginResponse(
                accessToken: loginResponse.accessToken,
                refreshToken: loginResponse.refreshToken,
                expiresIn: loginResponse.expiresIn,
                user: loginResponse.user,
                receivedAt: Date()
            )

            // Store tokens if token store is configured
            if let tokenStore = tokenStore {
                try tokenStore.saveTokens(loginResponse.toTokenResponse())
            }

            return loginResponse

        case 401, 403:
            // Check if MFA is required
            let decoder = JSONDecoder()
            // NOTE: Don't use .convertFromSnakeCase - error models have explicit CodingKeys

            // Try to decode as MFA error
            if let mfaError = try? decoder.decode(MFARequiredError.self, from: data), mfaError.mfaRequired {
                throw OAuth42Error.mfaRequired(mfaError.errorDescription ?? "MFA code is required")
            }

            // Try to decode as standard error
            if let errorResponse = try? decoder.decode(OAuth2ErrorResponse.self, from: data) {
                throw OAuth42Error.invalidCredentials(errorResponse.errorDescription ?? "Invalid email or password")
            }

            throw OAuth42Error.invalidCredentials("Authentication failed")

        default:
            // Other errors
            let decoder = JSONDecoder()
            if let errorResponse = try? decoder.decode(OAuth2ErrorResponse.self, from: data) {
                throw OAuth42Error.loginFailed("\(errorResponse.error): \(errorResponse.errorDescription ?? "Unknown error")")
            }
            throw OAuth42Error.loginFailed("HTTP \(httpResponse.statusCode)")
        }
    }

    /// Get MFA status for the authenticated user
    /// - Returns: MFA status information
    public func getMFAStatus() async throws -> MFAStatus {
        let mfaStatusEndpoint = issuer.appending("/auth/mfa/status")
        guard let url = URL(string: mfaStatusEndpoint) else {
            throw OAuth42Error.invalidURL(mfaStatusEndpoint)
        }

        let (data, response) = try await makeAuthenticatedRequest(url: url)

        guard response.statusCode == 200 else {
            throw OAuth42Error.invalidResponse("HTTP \(response.statusCode)")
        }

        let decoder = JSONDecoder()
        // NOTE: Don't use .convertFromSnakeCase - MFAStatus has explicit CodingKeys
        decoder.dateDecodingStrategy = .iso8601

        return try decoder.decode(MFAStatus.self, from: data)
    }

    // MARK: - User Info

    /// Fetch user information using access token
    /// Automatically refreshes the token if it's expired or rejected by server.
    /// - Parameter accessToken: The access token (optional, will use stored token and auto-refresh if nil)
    /// - Returns: User information
    public func fetchUserInfo(accessToken: String? = nil) async throws -> UserInfo {
        let config = try await fetchConfiguration()

        guard let userinfoEndpoint = config.userinfoEndpoint else {
            throw OAuth42Error.invalidConfiguration("No userinfo endpoint in configuration")
        }

        // Transform the URL for local development (e.g., localhost -> IP)
        let transformedEndpoint = transformURL(userinfoEndpoint)
        guard let url = URL(string: transformedEndpoint) else {
            throw OAuth42Error.invalidURL(transformedEndpoint)
        }

        // Get the access token to use
        var accessTokenValue: String
        let wasProvidedToken: Bool

        if let provided = accessToken {
            // Use provided token as-is (caller's responsibility to ensure it's valid)
            accessTokenValue = provided
            wasProvidedToken = true
        } else {
            // Automatically get valid token, refreshing if necessary
            accessTokenValue = try await getValidAccessToken()
            wasProvidedToken = false
        }

        // First attempt
        var request = URLRequest(url: url)
        request.setValue("Bearer \(accessTokenValue)", forHTTPHeaderField: "Authorization")

        var (data, response) = try await urlSession.data(for: request)

        guard var httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        // If we get 401 and we weren't given a specific token, try to refresh and retry
        if httpResponse.statusCode == 401 && !wasProvidedToken {
            // Try to refresh the token
            if let tokens = try? getStoredTokens(), let refreshToken = tokens.refreshToken {
                do {
                    let refreshedTokens = try await refreshTokens(refreshToken: refreshToken)
                    accessTokenValue = refreshedTokens.accessToken

                    // Retry with refreshed token
                    request.setValue("Bearer \(accessTokenValue)", forHTTPHeaderField: "Authorization")
                    (data, response) = try await urlSession.data(for: request)

                    guard let retryResponse = response as? HTTPURLResponse else {
                        throw OAuth42Error.invalidResponse("Not an HTTP response")
                    }
                    httpResponse = retryResponse
                } catch {
                    // Refresh failed, throw original 401 error
                    throw OAuth42Error.invalidResponse("HTTP 401 (token refresh failed: \(error.localizedDescription))")
                }
            }
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

    private func normalizedProviders(_ providers: [String]) -> [String] {
        var seen = Set<String>()
        return providers.compactMap { provider in
            let normalized = provider.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !normalized.isEmpty, !seen.contains(normalized) else {
                return nil
            }
            seen.insert(normalized)
            return normalized
        }
    }

    private func hostedSocialError(statusCode: Int, data: Data, fallback: String) -> OAuth42Error {
        if let errorResponse = try? JSONDecoder().decode(OAuth2ErrorResponse.self, from: data) {
            return .hostedSocialAuthFailed("\(errorResponse.error): \(errorResponse.errorDescription ?? "Unknown error")")
        }

        if statusCode == 404 {
            return .hostedSocialAuthFailed(
                "\(fallback). Endpoint returned HTTP 404. Check hostedAuthBaseURL; for production hosted social auth use https://auth.oauth42.com."
            )
        }

        return .hostedSocialAuthFailed("\(fallback). HTTP \(statusCode)")
    }
}

private struct HostedSocialProvidersResponse: Codable {
    let providers: [String]
}

private struct HostedSocialAuthInitRequest: Codable {
    let provider: String
    let clientId: String
    let redirectURI: String
    let state: String
    let isSignup: Bool

    enum CodingKeys: String, CodingKey {
        case provider
        case clientId = "client_id"
        case redirectURI = "redirect_uri"
        case state
        case isSignup = "is_signup"
    }
}

private struct HostedSocialAuthInitResponse: Codable {
    let authorizationURL: String
    let state: String?

    enum CodingKeys: String, CodingKey {
        case authorizationURL = "authorization_url"
        case state
    }
}
