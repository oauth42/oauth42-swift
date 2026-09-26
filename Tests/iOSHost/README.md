# iOS Keychain test host

Run `make test-ios` from the repository root, or set `IOS_SIMULATOR_ID` to choose an installed iPhone simulator. Xcode and an installed iOS simulator runtime are required. The committed Xcode project needs no project generator or extra Ruby packages.

The host links the production Swift sources and all portable XCTest sources. Its simulator-only ad-hoc signature and test-only Keychain entitlement provide the application identity required by Security.framework. Hostless Swift Package tests return `errSecMissingEntitlement` for Keychain operations on iOS; those failures must not be skipped or replaced with an in-memory store.

The macOS Python subprocess HTTPS fixtures are excluded by `#if os(macOS)`; run `make test` to cover both platforms. When adding a source or portable test file, add it to this project's corresponding Sources build phase as well as the Swift package.
