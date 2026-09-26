# OAuth42 Swift SDK security audit

Reviewed September 26, 2026 on branch `fix/security-audit`. Scope: every production Swift source file, package dependencies, examples, token persistence, OIDC/code/password/refresh flows, hosted social initiation, authenticated requests, and provider logout. This is a source and regression-test review of the SDK, not a certification of an integrating application or the OAuth42 server.

## Findings and fixes

| ID | Severity | Finding and resulting behavior | Regression evidence |
| --- | --- | --- | --- |
| SW-01 | High | Password login printed entire responses and headers, including access/refresh tokens, cookies and personal data. Removed these logs and bearer-token logging from README examples. | `testPasswordAuthenticationDoesNotWriteSecretsToStdout` captures actual login stdout and checks response/header/password sentinels. |
| SW-02 | High | Discovery issuer and credential endpoints were trusted without validation; HTTP and automatic redirects could send credentials to unintended destinations. Require exact issuer, HTTPS without userinfo/fragments, and issuer-origin authorization/token/userinfo/JWKS endpoints. Reject redirects before forwarding credentials. Disable SDK response caching and cookie persistence. Explicit additional HTTPS resource origins are required for custom bearer requests. | Discovery mix-up, HTTP, userinfo URL, foreign host/port and fragment negatives; real TLS certificate acceptance/rejection and same/cross-origin HTTP 307 tests verify the receiving endpoint sees zero requests. |
| SW-03 | High | OIDC ID tokens and caller-supplied nonces were never validated. OpenID authorization now generates a nonce by default and requires a valid RS256 ID token before persistence. Verify issuer-pinned JWKS signature, unique key ID, RSA key size, issuer, audience/authorized party, subject, expiration, issuance/not-before times, nonce and optional access-token hash. Reject unsigned/HS256 tokens and token-supplied key URLs. Refresh and userinfo cannot substitute the authenticated subject. | Fresh Security.framework RSA signatures; tampering, malformed JWTs, wrong claims/nonce/keys, weak or substituted algorithms, untrusted key URLs, missing ID token, refresh subject and userinfo subject tests; successful end-to-end mocked OIDC exchange persists the verified token. |
| SW-04 | Medium | `.urlQueryAllowed` left form delimiters unescaped, allowing values containing `&`, `+` or `=` to change token request parameters. Encode only RFC 3986 unreserved characters. | Actual code-exchange request tests include delimiter injection and Unicode in credentials and redirect URI. |
| SW-05 | High | Pending state/PKCE could be reused concurrently or after failure; in-flight responses could restore a logged-out session. Lock transaction state, consume it before network I/O, expire pending login after ten minutes, reject overlapping login/token operations, and invalidate pending login and in-flight persistence on `clearTokens()`. Cancelled tasks cannot persist tokens. | Wrong-state/no-network, failed-exchange replay, concurrent exchange/refresh, and deterministic logout-during-response tests. |
| SW-06 | Medium | Keychain save deleted the old session before attempting the replacement. Use atomic `SecItemUpdate`, adding only when absent. Request `WhenUnlockedThisDeviceOnly` protection on Apple mobile platforms. | Real Keychain overwrite/round-trip tests and persistent-reference preservation. The mobile test additionally checks the accessibility attribute. |
| SW-07 | Medium | Malformed bearer responses were accepted, refresh responses could discard omitted refresh credentials, and userinfo was not bound to the authenticated identity. Validate token type/nonempty values/positive lifetime; retain omitted refresh and ID tokens; enforce subject continuity. | Invalid-response persistence checks, refresh omission/subject-change tests, and userinfo substitution test. |

Provider browser logout presentation is now isolated to the main actor. PKCE already used SHA-256 and Swift's system random generator; no replacement PRNG was needed. The package has no third-party dependencies; cryptography uses CryptoKit and Security.framework. No embedded production credentials or plaintext token store were found in production sources.

## Standards comparison

Reviewed against [OWASP MASVS](https://mas.owasp.org/MASVS/), the [MASVS control catalog](https://github.com/OWASP/masvs/blob/master/OWASP_MASVS.yaml), [OIDC Core ID-token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation), and the [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html). Mapping below describes evidence and applicability; it does not claim full MASVS/ASVS conformance.

| Area | SDK evidence / application boundary |
| --- | --- |
| MASVS-STORAGE | Keychain persistence, atomic replacement, no SDK credential logs/cache/cookie persistence. Integrators must protect custom TokenStore implementations and their own logs/backups. |
| MASVS-CRYPTO | System CSPRNG-backed PKCE/state/nonce; SHA-256; platform RSA signature verification; issuer-pinned JWKS. Only RS256 is supported for ID tokens. |
| MASVS-AUTH | One-time expiring code transaction, PKCE S256, nonce and claims verification, subject continuity, refresh serialization, logout invalidation. Server authorization, throttling and MFA policy belong to the backend audit. |
| MASVS-NETWORK | HTTPS endpoint policy, platform TLS validation, redirect rejection and explicit bearer origins. Custom caller-provided TLS delegates remain a trust boundary; never install a production delegate that accepts arbitrary certificates. |
| MASVS-PLATFORM | Uses system browser session for provider logout and Keychain for secrets. Login browser presentation, callback URL ownership/registration, entitlements and Universal Links are responsibilities of the integrating app. |
| MASVS-CODE | Bounded JWT/JWKS parsing, response validation, meaningful adversarial and transport tests; no package dependencies. The caller's binary signing and update policy are outside this library. |
| MASVS-PRIVACY | Removed SDK response logging and example token logging. Requested scopes and application data retention/consent are app responsibilities. |
| MASVS-RESILIENCE | No claim of jailbreak detection, anti-tamper or obfuscation. Those controls require an application threat model and executable, not a source SDK. |

The macOS login Keychain does not expose iOS data-protection accessibility attributes; its security follows the user's login Keychain and ACLs. `ThisDeviceOnly` is not a claim about macOS backup behavior. Existing mobile entries receive the stricter accessibility class on their next successful save. The SDK does not revoke already-issued server tokens on local logout; provider logout additionally clears the browser session through the server.

## Verification

- `swift test`: 52 tests passed, zero failures and zero skips on macOS, including 14 adversarial security tests.
- The three macOS transport tests generate a one-day SHA-256 TLS certificate and run an isolated Python HTTPS server. Trust is restricted to that fixture certificate with normal hostname validation. They require Python 3 and `/usr/bin/openssl`; no live backend is required.
- `xcodebuild test` with the committed signed simulator test host: 49 portable tests passed on iOS 26.5, zero failures, including mobile Keychain accessibility and persistent-reference checks. HTTPS subprocess fixtures are macOS-only because iOS cannot launch the fixture server.

Reproduce:

```sh
swift test
make test-ios
swift build -c release
```

The hostless package runner was also attempted and failed Keychain tests with `errSecMissingEntitlement`; the signed simulator host fixes this fixture limitation without skipping tests. Select an installed simulator with `xcrun simctl list devices available` if its name differs. These checks do not test hardware lock-state/backup restoration, a consuming app's entitlements, or its browser callback registration. The broader OAuth42 server OWASP audit remains tracked separately in [oauth42/oauth42#628](https://github.com/oauth42/oauth42/issues/628).

## Compatibility notes

- Use HTTPS issuer and hosted-auth URLs. Discovered endpoints must share the configured issuer origin; URL transformers must preserve HTTPS and the transformed issuer origin.
- OpenID exchanges now reject missing/invalid ID tokens. For an OAuth-only provider, explicitly omit `openid` from scopes.
- One login/token mutation can be active per client. An overlapping operation fails explicitly; callers can wait/retry. `clearTokens()` cancels a pending login. A failed code exchange requires a new login.
- Add additional resource API origins through `allowedResourceOrigins`; never allow an origin based on an untrusted URL parameter.
- The SDK keeps an omitted previous ID token during refresh for identity continuity; this does not renew that ID token's expiration.
- Mobile Keychain access is unavailable while the device is locked. Background refresh designs must account for that policy.
