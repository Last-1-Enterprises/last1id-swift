import Foundation

enum Base64URL {
    static func encode(_ data: Data) -> String {
        let raw = data.base64EncodedString()
        return raw
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ string: String) -> Data? {
        guard string.count <= 16_384 else { return nil }
        var padded = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if padded.contains(where: { !$0.isBase64 }) {
            return nil
        }
        let remainder = padded.count % 4
        if remainder == 1 { return nil }
        if remainder > 0 {
            padded.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: padded)
    }
}

private extension Character {
    var isBase64: Bool {
        guard let ascii = unicodeScalars.first, unicodeScalars.count == 1 else { return false }
        let value = ascii.value
        return (value >= 65 && value <= 90)
            || (value >= 97 && value <= 122)
            || (value >= 48 && value <= 57)
            || value == 43
            || value == 47
            || value == 61
    }
}
