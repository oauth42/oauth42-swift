import CryptoKit
import Foundation
import Security

/// O42's supported OIDC profile: RS256, issuer-pinned JWKS, and authorization-code flow.
enum IDTokenValidator {
    static func decode(_ value: String) -> Data? {
        guard !value.isEmpty,
            value.utf8.allSatisfy({
                (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45
                    || $0 == 95
            })
        else { return nil }
        let base = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(
            of: "_", with: "/")
        return Data(base64Encoded: base + String(repeating: "=", count: (4 - base.count % 4) % 4))
    }

    static func validate(
        _ token: String, jwks: Data, issuer: String, clientID: String,
        nonce: String?, accessToken: String, now: Date = Date()
    ) throws {
        func invalid() -> OAuth42Error { .invalidResponse("ID token validation failed") }
        guard token.utf8.count <= 65536, jwks.count <= 1_048_576 else { throw invalid() }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, let headerData = decode(parts[0]), let claimsData = decode(parts[1]),
            let signature = decode(parts[2]),
            let header = try JSONSerialization.jsonObject(with: headerData) as? [String: Any],
            let claims = try JSONSerialization.jsonObject(with: claimsData) as? [String: Any],
            header["alg"] as? String == "RS256", header["crit"] == nil,
            header["jku"] == nil, header["jwk"] == nil, header["x5u"] == nil,
            let kid = header["kid"] as? String, !kid.isEmpty,
            let document = try JSONSerialization.jsonObject(with: jwks) as? [String: Any],
            let keys = document["keys"] as? [[String: Any]]
        else { throw invalid() }
        let matching = keys.filter { $0["kid"] as? String == kid }
        guard matching.count == 1, let jwk = matching.first,
            jwk["kty"] as? String == "RSA",
            jwk["use"] == nil || jwk["use"] as? String == "sig",
            jwk["alg"] == nil || jwk["alg"] as? String == "RS256",
            jwk["key_ops"] == nil || (jwk["key_ops"] as? [String])?.contains("verify") == true,
            let n = jwk["n"] as? String, let e = jwk["e"] as? String,
            let modulus = decode(n), let exponent = decode(e),
            (256...1024).contains(modulus.count), modulus.first ?? 0 >= 128,
            !exponent.isEmpty, exponent.count <= 8
        else { throw invalid() }
        let der = sequence(integer(modulus) + integer(exponent))
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil),
            SecKeyVerifySignature(
                key, .rsaSignatureMessagePKCS1v15SHA256,
                Data("\(parts[0]).\(parts[1])".utf8) as CFData,
                signature as CFData, nil)
        else { throw invalid() }
        let audience = (claims["aud"] as? [String]) ?? (claims["aud"] as? String).map { [$0] } ?? []
        let time = now.timeIntervalSince1970
        guard claims["iss"] as? String == issuer, audience.contains(clientID),
            let subject = claims["sub"] as? String, !subject.isEmpty,
            let expiry = number(claims["exp"]), expiry > time,
            let issued = number(claims["iat"]), issued <= time + 60, issued < expiry,
            audience.count <= 1 || claims["azp"] as? String == clientID,
            claims["azp"] == nil || claims["azp"] as? String == clientID
        else { throw invalid() }
        if let nonce = nonce, claims["nonce"] as? String != nonce { throw invalid() }
        if let notBefore = claims["nbf"] {
            guard let value = number(notBefore), value <= time + 60 else { throw invalid() }
        }
        if let hash = claims["at_hash"] {
            let digest = Data(SHA256.hash(data: Data(accessToken.utf8)).prefix(16))
            guard let value = hash as? String, decode(value) == digest else { throw invalid() }
        }
    }

    // Only for tokens already validated by this client or loaded from the application's trusted TokenStore.
    static func storedSubject(_ token: String) -> String? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let data = decode(String(parts[1])),
            let claims = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return claims["sub"] as? String
    }

    private static func number(_ value: Any?) -> Double? {
        guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
            value.doubleValue.isFinite
        else { return nil }
        return value.doubleValue
    }
    private static func length(_ count: Int) -> Data {
        if count < 128 { return Data([UInt8(count)]) }
        var value = count
        var bytes = [UInt8]()
        while value > 0 {
            bytes.insert(UInt8(value & 255), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
    private static func integer(_ value: Data) -> Data {
        var value = Data(value.drop(while: { $0 == 0 }))
        if value.isEmpty { value = Data([0]) }
        if value[0] >= 128 { value.insert(0, at: 0) }
        return Data([2]) + length(value.count) + value
    }
    private static func sequence(_ value: Data) -> Data { Data([0x30]) + length(value.count) + value }
}
