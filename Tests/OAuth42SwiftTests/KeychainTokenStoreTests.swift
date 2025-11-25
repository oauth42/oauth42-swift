import XCTest
@testable import OAuth42Swift

final class KeychainTokenStoreTests: XCTestCase {

    var tokenStore: KeychainTokenStore!
    let testService = "com.oauth42.tests"

    override func setUp() {
        super.setUp()
        tokenStore = KeychainTokenStore(service: testService)

        // Clean up any existing tokens
        try? tokenStore.deleteTokens()
    }

    override func tearDown() {
        // Clean up after tests
        try? tokenStore.deleteTokens()
        super.tearDown()
    }

    func testSaveAndRetrieveTokens() throws {
        let tokens = TokenResponse(
            accessToken: "test_access_token",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "test_refresh_token",
            scope: "openid profile email",
            idToken: "test_id_token"
        )

        // Save tokens
        try tokenStore.saveTokens(tokens)

        // Retrieve tokens
        let retrieved = try tokenStore.retrieveTokens()

        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.accessToken, tokens.accessToken)
        XCTAssertEqual(retrieved?.tokenType, tokens.tokenType)
        XCTAssertEqual(retrieved?.expiresIn, tokens.expiresIn)
        XCTAssertEqual(retrieved?.refreshToken, tokens.refreshToken)
        XCTAssertEqual(retrieved?.scope, tokens.scope)
        XCTAssertEqual(retrieved?.idToken, tokens.idToken)
    }

    func testDeleteTokens() throws {
        let tokens = TokenResponse(
            accessToken: "test_access_token",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "test_refresh_token",
            scope: nil,
            idToken: nil
        )

        // Save tokens
        try tokenStore.saveTokens(tokens)

        // Verify they exist
        var retrieved = try tokenStore.retrieveTokens()
        XCTAssertNotNil(retrieved)

        // Delete tokens
        try tokenStore.deleteTokens()

        // Verify they're gone
        retrieved = try tokenStore.retrieveTokens()
        XCTAssertNil(retrieved)
    }

    func testRetrieveNonExistentTokens() throws {
        let retrieved = try tokenStore.retrieveTokens()
        XCTAssertNil(retrieved)
    }

    func testOverwriteTokens() throws {
        let tokens1 = TokenResponse(
            accessToken: "access_token_1",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "refresh_token_1",
            scope: nil,
            idToken: nil
        )

        let tokens2 = TokenResponse(
            accessToken: "access_token_2",
            tokenType: "Bearer",
            expiresIn: 7200,
            refreshToken: "refresh_token_2",
            scope: "openid",
            idToken: "id_token_2"
        )

        // Save first tokens
        try tokenStore.saveTokens(tokens1)

        // Save second tokens (should overwrite)
        try tokenStore.saveTokens(tokens2)

        // Retrieve and verify we got the second tokens
        let retrieved = try tokenStore.retrieveTokens()
        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.accessToken, tokens2.accessToken)
        XCTAssertEqual(retrieved?.refreshToken, tokens2.refreshToken)
        XCTAssertEqual(retrieved?.expiresIn, tokens2.expiresIn)
        XCTAssertEqual(retrieved?.idToken, tokens2.idToken)
    }

    /// Test that receivedAt is persisted and restored correctly
    /// This is critical for accurate token expiration tracking (Issue #243)
    func testReceivedAtPersistence() throws {
        // Create tokens with a specific receivedAt time in the past
        let pastDate = Date(timeIntervalSinceNow: -1800)  // 30 minutes ago
        let tokens = TokenResponse(
            accessToken: "test_access_token",
            tokenType: "Bearer",
            expiresIn: 3600,  // 1 hour
            refreshToken: "test_refresh_token",
            scope: "openid",
            idToken: nil,
            receivedAt: pastDate
        )

        // Verify the token should not be considered expired yet (30 min old, 60 min TTL)
        XCTAssertFalse(tokens.isExpired(), "Fresh token should not be expired")

        // Save tokens to Keychain
        try tokenStore.saveTokens(tokens)

        // Retrieve tokens - this should preserve the original receivedAt
        let retrieved = try tokenStore.retrieveTokens()
        XCTAssertNotNil(retrieved)

        // Verify receivedAt was preserved (within 1 second tolerance for Date comparison)
        let timeDifference = abs(retrieved!.receivedAt.timeIntervalSince(pastDate))
        XCTAssertLessThan(timeDifference, 1.0, "receivedAt should be preserved after storage round-trip")

        // Verify the expiration check still works correctly with preserved timestamp
        XCTAssertFalse(retrieved!.isExpired(), "Token loaded from storage should not be expired")
    }

    /// Test that tokens with old receivedAt are correctly identified as expired
    /// This ensures the iOS app will properly trigger token refresh after restart
    func testExpiredTokenDetectionAfterStorage() throws {
        // Create tokens with a receivedAt time that makes them expired
        // Using expiresIn: 60 (1 minute) and receivedAt: 2 minutes ago
        let expiredDate = Date(timeIntervalSinceNow: -120)  // 2 minutes ago
        let tokens = TokenResponse(
            accessToken: "expired_access_token",
            tokenType: "Bearer",
            expiresIn: 60,  // 1 minute TTL
            refreshToken: "test_refresh_token",
            scope: "openid",
            idToken: nil,
            receivedAt: expiredDate
        )

        // Verify the token IS expired before saving
        XCTAssertTrue(tokens.isExpired(), "Token should be expired before saving")

        // Save to Keychain
        try tokenStore.saveTokens(tokens)

        // Retrieve from Keychain
        let retrieved = try tokenStore.retrieveTokens()
        XCTAssertNotNil(retrieved)

        // CRITICAL: After loading from storage, the token should STILL be expired
        // This is the bug fix for Issue #243 - previously receivedAt was reset to Date()
        // which made expired tokens appear valid
        XCTAssertTrue(retrieved!.isExpired(), "Expired token should remain expired after storage round-trip")
    }
}
