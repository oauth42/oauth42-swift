import Foundation

/// OpenID Connect Discovery Document
/// Corresponds to oidcDiscovery.schema.json
public struct OIDCConfiguration: Codable {
    public let issuer: String
    public let authorizationEndpoint: String
    public let tokenEndpoint: String
    public let userinfoEndpoint: String?
    public let jwksUri: String
    public let registrationEndpoint: String?
    public let introspectionEndpoint: String?
    public let revocationEndpoint: String?
    public let responseTypesSupported: [String]
    public let subjectTypesSupported: [String]
    public let idTokenSigningAlgValuesSupported: [String]
    public let scopesSupported: [String]?
    public let grantTypesSupported: [String]?
    public let codeChallengeMethodsSupported: [String]?
    public let tokenEndpointAuthMethodsSupported: [String]?
    public let claimsSupported: [String]?

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case userinfoEndpoint = "userinfo_endpoint"
        case jwksUri = "jwks_uri"
        case registrationEndpoint = "registration_endpoint"
        case introspectionEndpoint = "introspection_endpoint"
        case revocationEndpoint = "revocation_endpoint"
        case responseTypesSupported = "response_types_supported"
        case subjectTypesSupported = "subject_types_supported"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
        case scopesSupported = "scopes_supported"
        case grantTypesSupported = "grant_types_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
        case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
        case claimsSupported = "claims_supported"
    }
}
