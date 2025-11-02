import Foundation

/// Protocol for storing and retrieving OAuth tokens
public protocol TokenStore {
    /// Save tokens to secure storage
    func saveTokens(_ tokens: TokenResponse) throws

    /// Retrieve stored tokens
    func retrieveTokens() throws -> TokenResponse?

    /// Delete stored tokens
    func deleteTokens() throws
}
