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
}
