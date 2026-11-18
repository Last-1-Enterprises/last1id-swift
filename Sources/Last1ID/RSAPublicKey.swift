import Foundation
@preconcurrency import Security

struct RSAPublicKey: Sendable {
    var modulus: Data
    var exponent: Data
    var kid: String

    func secKey() throws -> SecKey {
        let encoded = DER.pkcs1PublicKey(modulus: modulus, exponent: exponent)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: modulus.count * 8,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(encoded as CFData, attributes as CFDictionary, &error) else {
            throw Last1IDError.idToken(.keyImportFailed)
        }
        return key
    }

    static func fromJWK(_ json: [String: Any]) -> RSAPublicKey? {
        guard Last1JSON.string(json["kty"]) == "RSA" else { return nil }
        if let use = Last1JSON.string(json["use"]), use != "sig" { return nil }
        if let alg = Last1JSON.string(json["alg"]), alg != "RS256" { return nil }
        guard let kid = Last1JSON.string(json["kid"]), !kid.isEmpty, kid.count <= 256,
              let nText = Last1JSON.string(json["n"]),
              let eText = Last1JSON.string(json["e"]),
              var modulus = Base64URL.decode(nText),
              var exponent = Base64URL.decode(eText) else {
            return nil
        }
        while modulus.first == 0, modulus.count > 1 { modulus.removeFirst() }
        while exponent.first == 0, exponent.count > 1 { exponent.removeFirst() }
        guard modulus.count >= 256, exponent.count >= 1, exponent.count <= 8 else { return nil }
        return RSAPublicKey(modulus: modulus, exponent: exponent, kid: kid)
    }
}

enum DER {
    static func pkcs1PublicKey(modulus: Data, exponent: Data) -> Data {
        sequence(integer(modulus) + integer(exponent))
    }

    static func modulusAndExponent(fromPKCS1 data: Data) throws -> (modulus: Data, exponent: Data) {
        var index = 0
        func byte() throws -> UInt8 {
            guard index < data.count else { throw Last1IDError.idToken(.keyImportFailed) }
            let value = data[index]
            index += 1
            return value
        }
        func length() throws -> Int {
            let first = try byte()
            if first < 0x80 { return Int(first) }
            let count = Int(first & 0x7F)
            guard (1...4).contains(count) else { throw Last1IDError.idToken(.keyImportFailed) }
            var value = 0
            for _ in 0..<count {
                value = (value << 8) | Int(try byte())
            }
            return value
        }
        func integerValue() throws -> Data {
            guard try byte() == 0x02 else { throw Last1IDError.idToken(.keyImportFailed) }
            let count = try length()
            guard count >= 0, index + count <= data.count else { throw Last1IDError.idToken(.keyImportFailed) }
            var bytes = data.subdata(in: index..<(index + count))
            index += count
            if bytes.first == 0x00 { bytes.removeFirst() }
            return bytes
        }
        guard try byte() == 0x30 else { throw Last1IDError.idToken(.keyImportFailed) }
        _ = try length()
        return (try integerValue(), try integerValue())
    }

    private static func sequence(_ content: Data) -> Data {
        Data([0x30]) + encodedLength(content.count) + content
    }

    private static func integer(_ data: Data) -> Data {
        var body = data
        while body.count > 1 && body.first == 0 { body.removeFirst() }
        if let first = body.first, first & 0x80 != 0 {
            body.insert(0x00, at: 0)
        }
        return Data([0x02]) + encodedLength(body.count) + body
    }

    private static func encodedLength(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }
        var value = length
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
    }
}
