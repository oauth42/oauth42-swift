// OAuth42Swift - Swift SDK for OAuth42 Authentication
//
// This SDK provides a comprehensive client library for integrating OAuth42
// authentication into iOS, macOS, tvOS, and watchOS applications.
//
// Features:
// - OAuth2 Authorization Code Flow with PKCE
// - Automatic token refresh (transparent to the developer)
// - Secure Keychain storage
// - OpenID Connect support
// - UserInfo endpoint integration
//
// Example usage:
//
//     let client = OAuth42Client(
//         clientId: "your-client-id",
//         redirectURI: "myapp://oauth-callback",
//         issuer: "https://oauth42.example.com",
//         tokenStore: KeychainTokenStore(service: "com.example.myapp")
//     )
//
//     // Build authorization URL
//     let authURL = try await client.buildAuthorizationURL()
//     // Open authURL in ASWebAuthenticationSession
//
//     // Exchange code for tokens (after redirect)
//     let tokens = try await client.exchangeCodeForTokens(code: code, state: state)
//
//     // Fetch user info (automatically refreshes token if expired)
//     let userInfo = try await client.fetchUserInfo()
//
//     // Make custom authenticated API requests (also auto-refreshes)
//     let (data, response) = try await client.makeAuthenticatedRequest(
//         url: URL(string: "https://api.example.com/custom-endpoint")!
//     )

/// Current SDK version
public let OAuth42SwiftVersion = "1.1.1"
