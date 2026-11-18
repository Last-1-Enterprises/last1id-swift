import Foundation

enum Last1JSON {
    static func object(from data: Data, maximumBytes: Int) -> [String: Any]? {
        guard data.count <= maximumBytes else { return nil }
        guard let value = try? JSONSerialization.jsonObject(with: data) else { return nil }
        return value as? [String: Any]
    }

    static func string(_ value: Any?) -> String? {
        value as? String
    }

    static func bool(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber else { return nil }
        if CFGetTypeID(number) != CFBooleanGetTypeID() { return nil }
        return number.boolValue
    }

    static func int64(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber else { return nil }
        if CFGetTypeID(number) == CFBooleanGetTypeID() { return nil }
        return number.int64Value
    }

    static func stringArray(_ value: Any?) -> [String]? {
        if let string = value as? String { return [string] }
        guard let array = value as? [Any] else { return nil }
        var strings: [String] = []
        strings.reserveCapacity(array.count)
        for item in array {
            guard let string = item as? String else { return nil }
            strings.append(string)
        }
        return strings
    }

    static func oauthDescription(_ value: Any?) -> String? {
        guard var text = value as? String else { return nil }
        text = text.replacingOccurrences(of: "\n", with: " ")
        if text.count > 300 {
            text = String(text.prefix(300))
        }
        return text
    }
}
