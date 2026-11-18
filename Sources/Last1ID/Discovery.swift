import Foundation

public struct Last1IDDiscovery: Sendable, Equatable {
    public let issuer: String
    public let authorizationEndpoint: URL
    public let tokenEndpoint: URL
    public let userinfoEndpoint: URL
    public let revocationEndpoint: URL
    public let jwksURI: URL
    public let responseTypesSupported: [String]
    public let idTokenSigningAlgValuesSupported: [String]
    public let tokenEndpointAuthMethodsSupported: [String]
    public let codeChallengeMethodsSupported: [String]
    public let promptValuesSupported: [String]

    static func parse(data: Data, expectedIssuer: String) throws -> Last1IDDiscovery {
        guard let json = Last1JSON.object(from: data, maximumBytes: 65_536) else {
            throw Last1IDError.discovery("document is not a JSON object")
        }
        let expected = Last1URL.issuerString(URL(string: expectedIssuer) ?? URL(fileURLWithPath: "/"))
        guard let issuerValue = Last1JSON.string(json["issuer"]) else {
            throw Last1IDError.discovery("issuer is missing")
        }
        let issuer = Last1URL.issuerString(URL(string: issuerValue) ?? URL(fileURLWithPath: "/"))
        guard issuer == expected else {
            throw Last1IDError.discovery("issuer does not match the configured issuer")
        }
        guard let issuerURL = URL(string: issuer), let host = issuerURL.host else {
            throw Last1IDError.discovery("issuer is not a URL")
        }

        func endpoint(_ key: String) throws -> URL {
            guard let text = Last1JSON.string(json[key]), let url = URL(string: text) else {
                throw Last1IDError.discovery("\(key) is missing")
            }
            guard Last1URL.sameOrigin(url, issuerHost: host) else {
                throw Last1IDError.discovery("\(key) is not an https URL on the issuer host")
            }
            return url
        }

        let responseTypes = Last1JSON.stringArray(json["response_types_supported"]) ?? []
        if !responseTypes.contains("code") {
            throw Last1IDError.discovery("response_types_supported does not include code")
        }
        let algorithms = Last1JSON.stringArray(json["id_token_signing_alg_values_supported"]) ?? []
        if !algorithms.contains("RS256") {
            throw Last1IDError.discovery("id_token_signing_alg_values_supported does not include RS256")
        }
        let authMethods = Last1JSON.stringArray(json["token_endpoint_auth_methods_supported"]) ?? []
        if !authMethods.contains("none") {
            throw Last1IDError.discovery("token_endpoint_auth_methods_supported does not include none")
        }
        let challenges = Last1JSON.stringArray(json["code_challenge_methods_supported"]) ?? []
        if !challenges.contains("S256") {
            throw Last1IDError.discovery("code_challenge_methods_supported does not include S256")
        }

        return Last1IDDiscovery(
            issuer: issuer,
            authorizationEndpoint: try endpoint("authorization_endpoint"),
            tokenEndpoint: try endpoint("token_endpoint"),
            userinfoEndpoint: try endpoint("userinfo_endpoint"),
            revocationEndpoint: try endpoint("revocation_endpoint"),
            jwksURI: try endpoint("jwks_uri"),
            responseTypesSupported: responseTypes,
            idTokenSigningAlgValuesSupported: algorithms,
            tokenEndpointAuthMethodsSupported: authMethods,
            codeChallengeMethodsSupported: challenges,
            promptValuesSupported: Last1JSON.stringArray(json["prompt_values_supported"]) ?? []
        )
    }
}
