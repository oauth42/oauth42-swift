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
    private struct Authorization {
        let pkce: PKCEManager.PKCEPair
        let state: String
        let nonce: String?
        let created: Date
    }
    private let lock = NSLock()
    private var pending: Authorization?
    var authorizationNow: () -> Date = Date.init  // Internal clock seam for expiry regression tests.
    private var generation = UUID()
    private var trustedSubject: String?
    private var trustedIDToken: String?
    private var trustedAccessToken: String?
    private var activeOperation: UUID?
    private let redirectDelegate = NoRedirectDelegate()
    private let resourceOrigins: [String]

    var defaultCallbackURLScheme: String? {
        URL(string: redirectURI)?.scheme
    }

    /// Initialize OAuth42Client
    /// - Parameters:
    ///   - clientId: OAuth2 client ID
    ///   - clientSecret: Optional client secret (for confidential clients)
    ///   - redirectURI: OAuth2 redirect URI (e.g., "myapp://oauth-callback")
    ///   - issuer: OAuth42 OIDC issuer URL (e.g., "https://api.oauth42.com")
    ///   - hostedAuthBaseURL: OAuth42 hosted auth URL for social sign-in (e.g., "https://auth.oauth42.com")
    ///   - scopes: Requested scopes (default: ["openid", "profile", "email"])
    ///   - tokenStore: Optional token store for persistence
    ///   - allowedResourceOrigins: Additional HTTPS origins explicitly authorized to receive bearer tokens.
    ///   - urlSession: Optional custom URLSession (its TLS delegate is preserved; redirects and caching are disabled)
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
        allowedResourceOrigins: [URL] = [],
        urlTransformer: ((String) -> String)? = nil
    ) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.issuer = OAuth42Client.normalizedBaseURL(issuer)
        self.hostedAuthBaseURL =
            hostedAuthBaseURL.map(OAuth42Client.normalizedBaseURL)
            ?? OAuth42Client.defaultHostedAuthBaseURL(for: issuer)
        self.scopes = scopes
        self.tokenStore = tokenStore
        let sessionConfiguration = urlSession.configuration
        sessionConfiguration.urlCache = nil
        sessionConfiguration.httpCookieStorage = nil
        sessionConfiguration.httpShouldSetCookies = false
        sessionConfiguration.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.urlSession = URLSession(
            configuration: sessionConfiguration, delegate: urlSession.delegate, delegateQueue: nil)
        self.resourceOrigins = allowedResourceOrigins.filter {
            (try? SecurityPolicy.httpsURL($0.absoluteString)) != nil && $0.query == nil
                && ($0.path.isEmpty || $0.path == "/")
        }.map(SecurityPolicy.origin)
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
            let host = components.host
        else {
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
        if let cached = synchronized({ configuration }) {
            return cached
        }

        let discoveryURL = issuer.appending("/.well-known/openid-configuration")
        let url = try endpoint(discoveryURL)

        let (data, response) = try await send(URLRequest(url: url))

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
        guard config.issuer == issuer, config.responseTypesSupported.contains("code"),
            config.idTokenSigningAlgValuesSupported.contains("RS256")
        else {
            throw OAuth42Error.invalidConfiguration("Discovery issuer or supported OIDC profile mismatch")
        }
        for value in [config.authorizationEndpoint, config.tokenEndpoint, config.jwksUri]
            + [config.userinfoEndpoint].compactMap({ $0 })
        {
            _ = try endpoint(value)
        }
        synchronized { self.configuration = config }
        return config
    }

    // MARK: - Authorization

    /// Build authorization URL for starting OAuth2 flow
    /// - Parameters:
    ///   - state: Optional state parameter for CSRF protection.
    ///   - nonce: Optional nonce for OpenID Connect ID token replay protection.
    /// - Returns: Authorization URL to open in browser
    public func buildAuthorizationURL(state: String? = nil, nonce: String? = nil) async throws -> URL {
        let config = try await fetchConfiguration()

        let transaction = try beginAuthorization(state: state, nonce: nonce)
        let pkce = transaction.pkce
        let stateValue = transaction.state

        // Build query parameters (transform URL for local development)
        var components = URLComponents(
            url: try endpoint(config.authorizationEndpoint), resolvingAgainstBaseURL: false)
        var queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "scope", value: scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: stateValue),
            URLQueryItem(name: "code_challenge", value: pkce.codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: pkce.codeChallengeMethod),
        ]
        if let nonce = transaction.nonce {
            queryItems.append(URLQueryItem(name: "nonce", value: nonce))
        }
        components?.queryItems = queryItems

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
        _ = try SecurityPolicy.httpsURL(hostedAuthBaseURL)

        guard
            var components = URLComponents(
                string: hostedAuthBaseURL.appending("/api/social-providers")
            )
        else {
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

        let (data, response) = try await send(URLRequest(url: url))
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

    /// Build a provider authorization URL for direct OAuth42 social sign-in.
    ///
    /// This starts the same OAuth2 Authorization Code + PKCE transaction as
    /// `buildAuthorizationURL`, then asks OAuth42 hosted auth for a provider
    /// URL while preserving the original `scope`, `state`, PKCE challenge, and
    /// `nonce`. Open the returned URL in a browser or `ASWebAuthenticationSession`,
    /// then pass the app callback's `code` and `state` to
    /// `exchangeCodeForTokens(code:state:)`.
    ///
    /// - Parameters:
    ///   - provider: Social provider identifier such as `google`, `github`, or `apple`.
    ///   - isSignup: Whether the hosted flow should be treated as signup.
    ///   - state: Optional state parameter for CSRF protection.
    ///   - nonce: Optional nonce for OpenID Connect ID token replay protection.
    /// - Returns: Provider authorization URL to open in a browser or ASWebAuthenticationSession.
    public func buildSocialAuthorizationURL(
        provider: String,
        isSignup: Bool = false,
        state: String? = nil,
        nonce: String? = nil
    ) async throws -> URL {
        try await buildHostedSocialAuthorizationURL(
            provider: provider,
            isSignup: isSignup,
            state: state,
            nonce: nonce
        )
    }

    /// Build a provider authorization URL for OAuth42 hosted social sign-in.
    /// - Parameters:
    ///   - provider: Social provider identifier such as `google`, `github`, or `apple`.
    ///   - isSignup: Whether the hosted flow should be treated as signup.
    ///   - state: Optional state parameter for CSRF protection.
    ///   - nonce: Optional nonce for OpenID Connect ID token replay protection.
    /// - Returns: Provider authorization URL to open in a browser or ASWebAuthenticationSession.
    public func buildHostedSocialAuthorizationURL(
        provider: String,
        isSignup: Bool = false,
        state: String? = nil,
        nonce: String? = nil
    ) async throws -> URL {
        _ = try await fetchConfiguration()
        _ = try SecurityPolicy.httpsURL(hostedAuthBaseURL)

        guard let url = URL(string: transformURL(hostedAuthBaseURL.appending("/api/social-auth/init")))
        else {
            throw OAuth42Error.invalidURL(hostedAuthBaseURL)
        }

        let transaction = try beginAuthorization(state: state, nonce: nonce)
        let pkce = transaction.pkce
        let stateValue = transaction.state

        let payload = HostedSocialAuthInitRequest(
            provider: provider.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            clientId: clientId,
            redirectURI: redirectURI,
            state: stateValue,
            scope: scopes.joined(separator: " "),
            codeChallenge: pkce.codeChallenge,
            codeChallengeMethod: pkce.codeChallengeMethod,
            nonce: transaction.nonce,
            isSignup: isSignup
        )

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONEncoder().encode(payload)

        do {
            let (data, response) = try await send(request)
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
            let authorizationURL = try SecurityPolicy.httpsURL(providerResponse.authorizationURL)
            guard synchronized({ pending?.state == stateValue }) else { throw OAuth42Error.invalidState }
            return authorizationURL
        } catch {
            synchronized { if pending?.state == stateValue { pending = nil } }
            throw error
        }
    }

    // MARK: - Logout

    /// Build the OAuth42 provider-level logout URL.
    ///
    /// This lower-level helper is useful when an app owns browser presentation
    /// itself. On Apple platforms that use `ASWebAuthenticationSession`, prefer
    /// the SDK-provided `signOut(presentationContextProvider:...)` method so
    /// token clearing and provider logout stay in one consistent flow.
    ///
    /// - Parameter redirectURI: Optional URI OAuth42 redirects to after logout.
    ///   Defaults to the client's redirect URI.
    /// - Returns: Logout URL to open in a browser or web authentication session.
    public func buildProviderLogoutURL(redirectURI: String? = nil) throws -> URL {
        let logout = try endpoint(issuer.appending("/auth/logout"))
        guard var components = URLComponents(url: logout, resolvingAgainstBaseURL: false) else {
            throw OAuth42Error.invalidURL("Failed to build provider logout URL")
        }

        components.queryItems = [
            URLQueryItem(name: "redirect_uri", value: redirectURI ?? self.redirectURI)
        ]

        guard let url = components.url else {
            throw OAuth42Error.invalidURL("Failed to build provider logout URL")
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
        let (transaction, operation) = try consumeAuthorization(state: state)
        defer { endOperation(operation) }
        let pkce = transaction.pkce
        let config = try await fetchConfiguration()

        // Transform the URL for local development (e.g., localhost -> IP)
        let url = try endpoint(config.tokenEndpoint)

        // Build form parameters
        var parameters: [String: String] = [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirectURI,
            "client_id": clientId,
            "code_verifier": pkce.codeVerifier,
        ]

        if let clientSecret = clientSecret {
            parameters["client_secret"] = clientSecret
        }

        let tokens = try await performTokenRequest(url: url, parameters: parameters)

        try await validateIDToken(
            tokens, config: config, nonce: transaction.nonce, required: scopes.contains("openid"))
        try save(tokens, operation: operation)

        return tokens
    }

    // MARK: - Token Refresh

    /// Refresh access token using refresh token
    /// - Parameter refreshToken: The refresh token (optional, will use stored token if nil)
    /// - Returns: New token response
    public func refreshTokens(refreshToken: String? = nil) async throws -> TokenResponse {
        let operation = try beginOperation()
        defer { endOperation(operation) }
        let refreshTokenValue: String

        if let provided = refreshToken {
            refreshTokenValue = provided
        } else if let stored = try getStoredTokens()?.refreshToken {
            refreshTokenValue = stored
        } else {
            throw OAuth42Error.missingRefreshToken
        }

        let config = try await fetchConfiguration()

        // Transform the URL for local development (e.g., localhost -> IP)
        let url = try endpoint(config.tokenEndpoint)

        var parameters: [String: String] = [
            "grant_type": "refresh_token",
            "refresh_token": refreshTokenValue,
            "client_id": clientId,
        ]

        if let clientSecret = clientSecret {
            parameters["client_secret"] = clientSecret
        }

        let previous = try getStoredTokens()
        let previousIDToken = previous?.idToken ?? synchronized { trustedIDToken }
        let response = try await performTokenRequest(url: url, parameters: parameters)
        try await validateIDToken(response, config: config, nonce: nil, required: false)
        let previousSubject =
            synchronized { trustedSubject } ?? previous?.idToken.flatMap(IDTokenValidator.storedSubject)
        if let idToken = response.idToken, let previousSubject = previousSubject,
            IDTokenValidator.storedSubject(idToken) != previousSubject
        {
            throw OAuth42Error.invalidResponse("Refresh changed the authenticated subject")
        }
        let tokens = TokenResponse(
            accessToken: response.accessToken, tokenType: response.tokenType,
            expiresIn: response.expiresIn, refreshToken: response.refreshToken ?? refreshTokenValue,
            scope: response.scope ?? previous?.scope, idToken: response.idToken ?? previousIDToken,
            receivedAt: response.receivedAt)
        try save(tokens, operation: operation)

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
        let operation = try beginOperation()
        defer { endOperation(operation) }
        // Build login endpoint URL
        // The login endpoint is typically at /auth/login or /login
        let loginEndpoint = issuer.appending("/auth/login")
        let url = try endpoint(loginEndpoint)

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

        let (data, response) = try await send(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        // Handle different response codes
        switch httpResponse.statusCode {
        case 200:
            // Success - decode login response
            let decoder = JSONDecoder()
            // NOTE: Don't use .convertFromSnakeCase here because LoginResponse and UserInfo
            // already have explicit CodingKeys that handle snake_case mapping
            decoder.dateDecodingStrategy = .iso8601

            var loginResponse = try decoder.decode(LoginResponse.self, from: data)

            // Ensure receivedAt is set to current time
            loginResponse = LoginResponse(
                accessToken: loginResponse.accessToken,
                refreshToken: loginResponse.refreshToken,
                expiresIn: loginResponse.expiresIn,
                user: loginResponse.user,
                receivedAt: Date()
            )

            try save(loginResponse.toTokenResponse(), operation: operation)

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
                throw OAuth42Error.invalidCredentials(
                    errorResponse.errorDescription ?? "Invalid email or password")
            }

            throw OAuth42Error.invalidCredentials("Authentication failed")

        default:
            // Other errors
            let decoder = JSONDecoder()
            if let errorResponse = try? decoder.decode(OAuth2ErrorResponse.self, from: data) {
                throw OAuth42Error.loginFailed(
                    "\(errorResponse.error): \(errorResponse.errorDescription ?? "Unknown error")")
            }
            throw OAuth42Error.loginFailed("HTTP \(httpResponse.statusCode)")
        }
    }

    /// Get MFA status for the authenticated user
    /// - Returns: MFA status information
    public func getMFAStatus() async throws -> MFAStatus {
        let mfaStatusEndpoint = issuer.appending("/auth/mfa/status")
        let url = try endpoint(mfaStatusEndpoint)

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
        let url = try endpoint(userinfoEndpoint)

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

        var (data, response) = try await send(request)

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
                    (data, response) = try await send(request)

                    guard let retryResponse = response as? HTTPURLResponse else {
                        throw OAuth42Error.invalidResponse("Not an HTTP response")
                    }
                    httpResponse = retryResponse
                } catch {
                    // Refresh failed, throw original 401 error
                    throw OAuth42Error.invalidResponse(
                        "HTTP 401 (token refresh failed: \(error.localizedDescription))")
                }
            }
        }

        guard httpResponse.statusCode == 200 else {
            throw OAuth42Error.invalidResponse("HTTP \(httpResponse.statusCode)")
        }

        let decoder = JSONDecoder()
        let user = try decoder.decode(UserInfo.self, from: data)
        let stored = try getStoredTokens()
        let expected =
            synchronized { trustedAccessToken == accessTokenValue ? trustedSubject : nil }
            ?? (stored?.accessToken == accessTokenValue
                ? stored?.idToken.flatMap(IDTokenValidator.storedSubject) : nil)
        if let expected = expected, user.id != expected {
            throw OAuth42Error.invalidResponse("Userinfo subject does not match the ID token")
        }
        return user
    }

    // MARK: - Token Management

    /// Get stored tokens if available
    public func getStoredTokens() throws -> TokenResponse? {
        return try synchronized { try tokenStore?.retrieveTokens() }
    }

    /// Clear stored tokens
    public func clearTokens() throws {
        try synchronized {
            generation = UUID()
            pending = nil
            trustedSubject = nil
            trustedIDToken = nil
            trustedAccessToken = nil
            try tokenStore?.deleteTokens()
        }
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
        _ = try SecurityPolicy.httpsURL(url.absoluteString)
        let origin = SecurityPolicy.origin(url)
        guard
            origin == SecurityPolicy.origin(try SecurityPolicy.httpsURL(transformURL(issuer)))
                || resourceOrigins.contains(origin)
        else {
            throw OAuth42Error.invalidURL("Resource origin is not authorized to receive access tokens")
        }
        let accessToken = try await getValidAccessToken()

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let body = body {
            request.httpBody = body
        }

        let (data, response) = try await send(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        return (data, httpResponse)
    }

    // MARK: - Private Helpers

    deinit { urlSession.invalidateAndCancel() }

    private func synchronized<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    private func endpoint(_ value: String) throws -> URL {
        _ = try SecurityPolicy.endpoint(value, issuer: issuer)
        return try SecurityPolicy.endpoint(transformURL(value), issuer: transformURL(issuer))
    }

    private func send(_ request: URLRequest) async throws -> (Data, URLResponse) {
        guard let url = request.url else { throw OAuth42Error.invalidURL("Missing URL") }
        _ = try SecurityPolicy.httpsURL(url.absoluteString)
        var request = request
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        return try await urlSession.data(for: request, delegate: redirectDelegate)
    }

    private func beginAuthorization(state: String?, nonce: String?) throws -> Authorization {
        let transaction = Authorization(
            pkce: try PKCEManager.generatePKCEPair(),
            state: state ?? UUID().uuidString,
            nonce: nonce ?? (scopes.contains("openid") ? UUID().uuidString : nil), created: authorizationNow())
        return try synchronized {
            guard activeOperation == nil,
                pending == nil || authorizationNow().timeIntervalSince(pending!.created) > 600,
                !transaction.state.isEmpty, transaction.nonce?.isEmpty != true
            else {
                throw OAuth42Error.authorizationFailed(
                    "A login is already pending or the state/nonce is empty; clearTokens cancels pending login"
                )
            }
            pending = transaction
            return transaction
        }
    }

    private func consumeAuthorization(state: String) throws -> (Authorization, UUID) {
        try synchronized {
            guard activeOperation == nil, let transaction = pending, transaction.state == state,
                authorizationNow().timeIntervalSince(transaction.created) <= 600
            else { throw OAuth42Error.invalidState }
            pending = nil  // Single use, including failed exchanges.
            activeOperation = generation
            return (transaction, generation)
        }
    }

    private func beginOperation() throws -> UUID {
        try synchronized {
            guard activeOperation == nil else {
                throw OAuth42Error.authorizationFailed("A token operation is already in progress")
            }
            activeOperation = generation
            return generation
        }
    }

    private func endOperation(_ operation: UUID) {
        synchronized { if activeOperation == operation { activeOperation = nil } }
    }

    private func save(_ tokens: TokenResponse, operation: UUID) throws {
        try Task.checkCancellation()
        try SecurityPolicy.validate(tokens)
        try synchronized {
            guard generation == operation else {
                throw OAuth42Error.authorizationFailed("Session was cleared during authentication")
            }
            try tokenStore?.saveTokens(tokens)
            trustedSubject = tokens.idToken.flatMap(IDTokenValidator.storedSubject)
            trustedIDToken = tokens.idToken
            trustedAccessToken = tokens.accessToken
        }
    }

    private func validateIDToken(
        _ tokens: TokenResponse, config: OIDCConfiguration, nonce: String?, required: Bool
    ) async throws {
        guard let token = tokens.idToken else {
            if required { throw OAuth42Error.invalidResponse("Missing OpenID Connect ID token") }
            return
        }
        let (data, response) = try await send(URLRequest(url: endpoint(config.jwksUri)))
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw OAuth42Error.invalidResponse("Could not fetch issuer signing keys")
        }
        try IDTokenValidator.validate(
            token, jwks: data, issuer: issuer, clientID: clientId, nonce: nonce,
            accessToken: tokens.accessToken)
    }

    private func performTokenRequest(url: URL, parameters: [String: String]) async throws
        -> TokenResponse
    {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        // Build form body
        let formBody =
            parameters
            .map { key, value in
                let encodedKey =
                    key.addingPercentEncoding(
                        withAllowedCharacters: CharacterSet(
                            charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"))
                    ?? key
                let encodedValue =
                    value.addingPercentEncoding(
                        withAllowedCharacters: CharacterSet(
                            charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"))
                    ?? value
                return "\(encodedKey)=\(encodedValue)"
            }
            .joined(separator: "&")

        request.httpBody = formBody.data(using: .utf8)

        let (data, response) = try await send(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuth42Error.invalidResponse("Not an HTTP response")
        }

        // Check for error response
        if httpResponse.statusCode != 200 {
            if let errorResponse = try? JSONDecoder().decode(OAuth2ErrorResponse.self, from: data) {
                throw OAuth42Error.tokenExchangeFailed(
                    "\(errorResponse.error): \(errorResponse.errorDescription ?? "Unknown error")")
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

        try SecurityPolicy.validate(tokenResponse)
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
            return .hostedSocialAuthFailed(
                "\(errorResponse.error): \(errorResponse.errorDescription ?? "Unknown error")")
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
    let scope: String
    let codeChallenge: String
    let codeChallengeMethod: String
    let nonce: String?
    let isSignup: Bool

    enum CodingKeys: String, CodingKey {
        case provider
        case clientId = "client_id"
        case redirectURI = "redirect_uri"
        case state
        case scope
        case codeChallenge = "code_challenge"
        case codeChallengeMethod = "code_challenge_method"
        case nonce
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
