# OAuth42Swift

[![Swift](https://img.shields.io/badge/Swift-5.7+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS%20|%20tvOS%20|%20watchOS-blue.svg)](https://developer.apple.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive Swift SDK for integrating OAuth42 authentication into iOS, macOS, tvOS, and watchOS applications.

## Features

- ✅ **OAuth2 Authorization Code Flow** with PKCE (S256)
- ✅ **Automatic Token Refresh** - transparent and seamless
- ✅ **Secure Keychain Storage** - encrypted token persistence
- ✅ **OpenID Connect Support** - full OIDC discovery and UserInfo
- ✅ **Modern Swift** - async/await, Codable, and type-safe APIs
- ✅ **Cross-Platform** - iOS 14+, macOS 11+, tvOS 14+, watchOS 7+
- ✅ **Zero Dependencies** - pure Swift implementation

## Installation

### Swift Package Manager

Add OAuth42Swift to your project using Xcode:

1. **File → Add Package Dependencies**
2. Enter the repository URL:
   ```
   https://github.com/devxpod/oauth42-swift.git
   ```
3. Select version rule (e.g., "Up to Next Major: 1.0.0")
4. Click **Add Package**

Or add it to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/devxpod/oauth42-swift.git", from: "1.0.0")
]
```

## Quick Start

### 1. Import the SDK

```swift
import OAuth42Swift
```

### 2. Initialize the Client

```swift
let client = OAuth42Client(
    clientId: "your-client-id",
    redirectURI: "myapp://oauth-callback",
    issuer: "https://oauth42.example.com",
    tokenStore: KeychainTokenStore(service: "com.example.myapp")
)
```

### 3. Perform Authentication

```swift
// Build authorization URL
let authURL = try await client.buildAuthorizationURL()

// Open in ASWebAuthenticationSession (iOS/macOS)
// ... handle user authentication in browser ...

// Exchange authorization code for tokens
let tokens = try await client.exchangeCodeForTokens(
    code: authorizationCode,
    state: stateFromRedirect
)

// Fetch user information (automatically refreshes token if needed)
let userInfo = try await client.fetchUserInfo()
print("Logged in as: \(userInfo.email)")
```

## Detailed Usage

### Configuration

#### Basic Configuration

```swift
let client = OAuth42Client(
    clientId: "your-client-id",
    redirectURI: "myapp://oauth-callback",
    issuer: "https://oauth42.example.com"
)
```

#### With Secure Token Storage

```swift
let tokenStore = KeychainTokenStore(
    service: "com.example.myapp",
    accessGroup: nil  // Optional: for sharing between apps
)

let client = OAuth42Client(
    clientId: "your-client-id",
    clientSecret: "your-secret",  // Optional for confidential clients
    redirectURI: "myapp://oauth-callback",
    issuer: "https://oauth42.example.com",
    scopes: ["openid", "profile", "email"],  // Default scopes
    tokenStore: tokenStore
)
```

### Authentication Flow

#### Step 1: Build Authorization URL

```swift
do {
    let authURL = try await client.buildAuthorizationURL()
    // Open authURL in browser or ASWebAuthenticationSession
} catch {
    print("Failed to build auth URL: \(error)")
}
```

#### Step 2: Handle Redirect (iOS/macOS)

Use `ASWebAuthenticationSession` for secure browser-based authentication:

```swift
import AuthenticationServices

func authenticate() {
    Task {
        do {
            let authURL = try await client.buildAuthorizationURL()

            let session = ASWebAuthenticationSession(
                url: authURL,
                callbackURLScheme: "myapp"
            ) { callbackURL, error in
                Task {
                    await self.handleCallback(callbackURL: callbackURL, error: error)
                }
            }

            session.presentationContextProvider = self
            session.start()

        } catch {
            print("Authentication error: \(error)")
        }
    }
}

func handleCallback(callbackURL: URL?, error: Error?) async {
    guard let callbackURL = callbackURL else {
        print("Authentication cancelled or failed: \(String(describing: error))")
        return
    }

    // Parse query parameters
    guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
          let queryItems = components.queryItems else {
        return
    }

    let code = queryItems.first { $0.name == "code" }?.value
    let state = queryItems.first { $0.name == "state" }?.value

    guard let code = code, let state = state else {
        print("Missing code or state in callback")
        return
    }

    do {
        // Exchange code for tokens
        let tokens = try await client.exchangeCodeForTokens(code: code, state: state)
        print("Authentication successful! Access token: \(tokens.accessToken)")

        // Fetch user info
        let userInfo = try await client.fetchUserInfo()
        print("Logged in as: \(userInfo.email)")

    } catch {
        print("Token exchange failed: \(error)")
    }
}
```

### Token Management

#### Automatic Token Refresh

The SDK automatically refreshes tokens when they expire:

```swift
// This automatically refreshes the token if expired
let userInfo = try await client.fetchUserInfo()
```

#### Manual Token Refresh

```swift
// Manually refresh tokens
let newTokens = try await client.refreshTokens()
print("New access token: \(newTokens.accessToken)")
```

#### Get Valid Access Token

```swift
// Get a valid token (automatically refreshes if expired)
let accessToken = try await client.getValidAccessToken()
```

#### Check Token Status

```swift
if let tokens = try client.getStoredTokens() {
    if tokens.isExpired() {
        print("Token is expired, will auto-refresh on next API call")
    } else {
        print("Token is valid for \(tokens.expiresAt.timeIntervalSinceNow) seconds")
    }
}
```

#### Clear Tokens (Logout)

```swift
do {
    try client.clearTokens()
    print("Logged out successfully")
} catch {
    print("Failed to clear tokens: \(error)")
}
```

### Making API Requests

#### Fetch User Information

```swift
// Using stored tokens (auto-refresh)
let userInfo = try await client.fetchUserInfo()
print("User: \(userInfo.email)")

// Using explicit access token
let userInfo = try await client.fetchUserInfo(accessToken: "explicit-token")
```

#### Custom API Requests

Use `makeAuthenticatedRequest()` for custom API endpoints:

```swift
// GET request
let url = URL(string: "https://api.oauth42.com/v1/profile")!
let (data, response) = try await client.makeAuthenticatedRequest(url: url)

if response.statusCode == 200 {
    let profile = try JSONDecoder().decode(Profile.self, from: data)
    print("Profile loaded: \(profile)")
}
```

```swift
// POST request
let url = URL(string: "https://api.oauth42.com/v1/settings")!
let payload = ["theme": "dark", "notifications": true]
let body = try JSONEncoder().encode(payload)

let (data, response) = try await client.makeAuthenticatedRequest(
    url: url,
    method: "POST",
    body: body
)
```

### SwiftUI Integration

```swift
import SwiftUI
import OAuth42Swift

@MainActor
class AuthManager: ObservableObject {
    @Published var isAuthenticated = false
    @Published var userInfo: UserInfo?
    @Published var error: Error?

    private let client: OAuth42Client

    init() {
        self.client = OAuth42Client(
            clientId: "your-client-id",
            redirectURI: "myapp://oauth-callback",
            issuer: "https://oauth42.example.com",
            tokenStore: KeychainTokenStore(service: "com.example.myapp")
        )

        // Check for existing session
        checkStoredSession()
    }

    func checkStoredSession() {
        Task {
            do {
                // Try to get stored tokens
                if let tokens = try client.getStoredTokens() {
                    // Fetch user info (will auto-refresh if needed)
                    self.userInfo = try await client.fetchUserInfo()
                    self.isAuthenticated = true
                }
            } catch {
                print("No valid session: \(error)")
            }
        }
    }

    func login() async {
        do {
            let authURL = try await client.buildAuthorizationURL()
            // Open authURL in ASWebAuthenticationSession
            // ... handle callback ...
        } catch {
            self.error = error
        }
    }

    func logout() {
        do {
            try client.clearTokens()
            self.isAuthenticated = false
            self.userInfo = nil
        } catch {
            self.error = error
        }
    }
}

// Usage in SwiftUI
struct ContentView: View {
    @StateObject private var auth = AuthManager()

    var body: some View {
        Group {
            if auth.isAuthenticated {
                ProfileView(userInfo: auth.userInfo)
            } else {
                LoginView(auth: auth)
            }
        }
    }
}
```

### Error Handling

The SDK provides comprehensive error types:

```swift
do {
    let userInfo = try await client.fetchUserInfo()
} catch OAuth42Error.authorizationFailed(let message) {
    print("Authorization failed: \(message)")
} catch OAuth42Error.networkError(let error) {
    print("Network error: \(error)")
} catch OAuth42Error.invalidState {
    print("Possible CSRF attack detected")
} catch OAuth42Error.missingRefreshToken {
    print("No refresh token available, re-authentication required")
} catch {
    print("Unknown error: \(error)")
}
```

Available error types:
- `invalidConfiguration(_:)` - Invalid SDK configuration
- `invalidURL(_:)` - Malformed URL
- `networkError(_:)` - Network/HTTP error
- `invalidResponse(_:)` - Invalid server response
- `authorizationFailed(_:)` - Authorization error
- `tokenExchangeFailed(_:)` - Token exchange error
- `refreshFailed(_:)` - Token refresh error
- `missingRefreshToken` - No refresh token available
- `keychainError(_:)` - Keychain storage error
- `pkceGenerationFailed` - PKCE generation error
- `invalidState` - State mismatch (CSRF protection)
- `userCancelled` - User cancelled authentication

## Advanced Usage

### Custom URLSession

For custom networking configuration (proxies, SSL pinning, etc.):

```swift
let configuration = URLSessionConfiguration.default
configuration.timeoutIntervalForRequest = 30

let customSession = URLSession(configuration: configuration)

let client = OAuth42Client(
    clientId: "your-client-id",
    redirectURI: "myapp://oauth-callback",
    issuer: "https://oauth42.example.com",
    urlSession: customSession
)
```

### App Groups (for Sharing Tokens)

Share tokens between your app and extensions:

```swift
let tokenStore = KeychainTokenStore(
    service: "com.example.myapp",
    accessGroup: "group.com.example.myapp"  // App Group ID
)
```

### Custom Scopes

```swift
let client = OAuth42Client(
    clientId: "your-client-id",
    redirectURI: "myapp://oauth-callback",
    issuer: "https://oauth42.example.com",
    scopes: ["openid", "profile", "email", "custom:read", "custom:write"]
)
```

### OIDC Discovery

The SDK automatically fetches and caches OIDC configuration:

```swift
let config = try await client.fetchConfiguration()
print("Authorization endpoint: \(config.authorizationEndpoint)")
print("Token endpoint: \(config.tokenEndpoint)")
print("Supported scopes: \(config.scopesSupported ?? [])")
```

## Platform-Specific Notes

### iOS

- Use `ASWebAuthenticationSession` for authentication
- Configure URL scheme in Info.plist:
  ```xml
  <key>CFBundleURLTypes</key>
  <array>
      <dict>
          <key>CFBundleURLSchemes</key>
          <array>
              <string>myapp</string>
          </array>
      </dict>
  </array>
  ```

### macOS

- Use `ASWebAuthenticationSession` for authentication
- May require entitlements for Keychain access

### tvOS

- Limited authentication options (device code flow recommended)
- Consider companion device authentication

### watchOS

- Token storage via Keychain
- Authentication typically handled on paired iPhone

## Requirements

- **iOS**: 14.0+
- **macOS**: 11.0+
- **tvOS**: 14.0+
- **watchOS**: 7.0+
- **Swift**: 5.7+
- **Xcode**: 14.0+

## Security Best Practices

1. **Always use PKCE** - The SDK enforces PKCE (S256) for all authorization flows
2. **Secure storage** - Use `KeychainTokenStore` for production apps
3. **State validation** - The SDK automatically generates and validates state parameters
4. **HTTPS only** - Never use OAuth42 over unencrypted HTTP in production
5. **Redirect URI validation** - Ensure your redirect URI is registered with OAuth42
6. **Token expiration** - The SDK handles token refresh with a 60-second safety buffer

## Testing

The SDK includes comprehensive test coverage:

```bash
# Run all tests
swift test

# Run specific test
swift test --filter OAuth42ClientTests
```

Test categories:
- Unit tests for all core functionality
- PKCE generation and validation
- Keychain storage operations
- Token expiration logic
- Integration tests (require running OAuth42 backend)

## Examples

See the [Examples](Examples/) directory for complete sample applications:
- **iOS-Example**: SwiftUI app with full authentication flow
- **macOS-Example**: AppKit-based macOS application

## Troubleshooting

### "Backend not running" in tests

Integration tests require a running OAuth42 backend:

```bash
cd ~/localdev/oauth42
make up-local-dev-ssl
make run-local-oauth42
```

### Keychain access errors

Ensure your app has proper Keychain entitlements and signing configuration.

### SSL certificate errors (local development)

For self-signed certificates in development, implement a custom `URLSessionDelegate`:

```swift
class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.host == "localhost" {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }
        completionHandler(.performDefaultHandling, nil)
    }
}

let session = URLSession(configuration: .default, delegate: InsecureDelegate(), delegateQueue: nil)
let client = OAuth42Client(..., urlSession: session)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This SDK is available under the MIT license. See the LICENSE file for more info.

## Support

- **Documentation**: https://docs.oauth42.com
- **Issues**: https://github.com/devxpod/oauth42-swift/issues
- **Main Project**: https://github.com/devxpod/oauth42

## Related Projects

- **OAuth42** - Main OAuth42 authentication server
- **OAuth42 Rust SDK** - Rust client library
- **OAuth42 Python SDK** - Python client library
- **OAuth42 TypeScript SDK** - TypeScript/JavaScript client library

---

**Made with ❤️ by the OAuth42 team**
