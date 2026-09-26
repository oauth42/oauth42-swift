import SwiftUI

// Test-only host gives XCTest the application identity required by the iOS Keychain.
@main
struct SecurityTestHost: App {
    var body: some Scene { WindowGroup { Text("OAuth42 security tests") } }
}
