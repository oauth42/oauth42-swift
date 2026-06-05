#if canImport(AuthenticationServices) && (os(iOS) || os(macOS) || targetEnvironment(macCatalyst))
import AuthenticationServices
import Foundation

@available(iOS 13.0, macOS 11.0, macCatalyst 13.0, *)
public extension OAuth42Client {
    /// Sign out of OAuth42 completely on Apple platforms.
    ///
    /// This clears locally stored tokens and then opens OAuth42 provider logout
    /// in `ASWebAuthenticationSession` so OAuth42 browser cookies and the
    /// server-side session registry are cleared. Use this for user-initiated
    /// sign-out when the next sign-in should allow account selection.
    ///
    /// For session-expired or background-auth-failure handling, call
    /// `clearTokens()` instead to avoid presenting a browser session.
    ///
    /// - Parameters:
    ///   - presentationContextProvider: Presentation anchor provider for the
    ///     web authentication session.
    ///   - redirectURI: Optional URI OAuth42 redirects to after logout.
    ///     Defaults to the client's redirect URI.
    ///   - callbackURLScheme: Optional callback scheme for
    ///     `ASWebAuthenticationSession`. Defaults to the scheme from the
    ///     client's redirect URI.
    ///   - prefersEphemeralWebBrowserSession: Passed through to
    ///     `ASWebAuthenticationSession`.
    func signOut(
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding,
        redirectURI: String? = nil,
        callbackURLScheme: String? = nil,
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws {
        try clearTokens()
        try await performProviderLogout(
            presentationContextProvider: presentationContextProvider,
            redirectURI: redirectURI,
            callbackURLScheme: callbackURLScheme,
            prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession
        )
    }

    /// Run OAuth42 provider logout without clearing local tokens.
    ///
    /// Most apps should call `signOut(presentationContextProvider:...)`
    /// instead. This method is provided for advanced flows that manage local
    /// token storage separately.
    func performProviderLogout(
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding,
        redirectURI: String? = nil,
        callbackURLScheme: String? = nil,
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws {
        let logoutURL = try buildProviderLogoutURL(redirectURI: redirectURI)
        let runner = OAuth42WebAuthenticationSessionRunner(
            presentationContextProvider: presentationContextProvider
        )

        try await runner.start(
            url: logoutURL,
            callbackURLScheme: callbackURLScheme ?? defaultCallbackURLScheme,
            prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession
        )
    }
}

@available(iOS 13.0, macOS 11.0, macCatalyst 13.0, *)
private final class OAuth42WebAuthenticationSessionRunner {
    private let presentationContextProvider: ASWebAuthenticationPresentationContextProviding
    private var session: ASWebAuthenticationSession?

    init(presentationContextProvider: ASWebAuthenticationPresentationContextProviding) {
        self.presentationContextProvider = presentationContextProvider
    }

    func start(
        url: URL,
        callbackURLScheme: String?,
        prefersEphemeralWebBrowserSession: Bool
    ) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: callbackURLScheme
            ) { [weak self] _, error in
                self?.session = nil

                if let authError = error as? ASWebAuthenticationSessionError,
                   authError.code == .canceledLogin {
                    continuation.resume(throwing: OAuth42Error.userCancelled)
                    return
                }

                if let error {
                    continuation.resume(throwing: OAuth42Error.authorizationFailed(error.localizedDescription))
                    return
                }

                continuation.resume(returning: ())
            }

            session.presentationContextProvider = presentationContextProvider
            session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession

            self.session = session
            guard session.start() else {
                self.session = nil
                continuation.resume(
                    throwing: OAuth42Error.authorizationFailed("Could not start provider logout session")
                )
                return
            }
        }
    }
}
#endif
