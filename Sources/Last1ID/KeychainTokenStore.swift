import Foundation
@preconcurrency import Security

/// Keychain store for one app client.
///
/// Items use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and are
/// not synchronized. On macOS the app must be signed with an app identifier,
/// or the Keychain returns -34018. The SDK does not log the item contents.
public struct Last1IDKeychainTokenStore: Last1IDTokenStore, Sendable {
    public static let defaultService = "id.last1.sdk"
    static let itemAccessibility = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String

    public let service: String
    public let account: String
    #if os(macOS)
    private let testingQueryFields: Last1IDKeychainTestingFields?
    #endif

    public init(service: String = Last1IDKeychainTokenStore.defaultService, account: String) {
        self.service = service
        self.account = account
        #if os(macOS)
        self.testingQueryFields = nil
        #endif
    }

    #if os(macOS)
    /// Test hook. `fields` are merged into every SecItem query. Tests pass
    /// a file keychain here. Production does not call this.
    init(service: String, account: String, testingQueryFields: [String: Any]) {
        self.service = service
        self.account = account
        self.testingQueryFields = Last1IDKeychainTestingFields(fields: testingQueryFields)
    }
    #endif

    public func load() async throws -> Last1IDTokens? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw Last1IDError.keychain(status)
        }
        guard let tokens = try? Last1TokenCoding.decoder().decode(Last1IDTokens.self, from: data) else {
            throw Last1IDError.storeFailed
        }
        return tokens
    }

    public func save(_ tokens: Last1IDTokens) async throws {
        let data: Data
        do {
            data = try Last1TokenCoding.encoder().encode(tokens)
        } catch {
            throw Last1IDError.storeFailed
        }
        let query = baseQuery()
        let existing = SecItemCopyMatching(query as CFDictionary, nil)
        if existing == errSecSuccess {
            var update: [String: Any] = [
                kSecValueData as String: data,
            ]
            if usesDataProtectionAttributes {
                update[kSecAttrAccessible as String] = Self.itemAccessibility
            }
            let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            guard status == errSecSuccess else { throw Last1IDError.keychain(status) }
            return
        }
        if existing != errSecItemNotFound {
            throw Last1IDError.keychain(existing)
        }
        var add = baseQuery()
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = "Last1 ID"
        if usesDataProtectionAttributes {
            add[kSecAttrAccessible as String] = Self.itemAccessibility
        }
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw Last1IDError.keychain(status) }
    }

    public func clear() async throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound { return }
        throw Last1IDError.keychain(status)
    }

    private var usesDataProtectionAttributes: Bool {
        #if os(macOS)
        testingQueryFields == nil
        #else
        true
        #endif
    }

    func testingBaseQuery() -> [String: Any] {
        baseQuery()
    }

    /// File keychains do not support `kSecAttrSynchronizable`. Setting it
    /// makes SecItem write one keychain and read another.
    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        #if os(macOS)
        if let testingQueryFields {
            for (key, value) in testingQueryFields.fields {
                query[key] = value
            }
        } else {
            query[kSecAttrSynchronizable as String] = false
            query[kSecUseDataProtectionKeychain as String] = true
        }
        #else
        query[kSecAttrSynchronizable as String] = false
        #endif
        return query
    }
}

#if os(macOS)
/// Holds SecItem fields that are not `Sendable`, such as a test file keychain.
private struct Last1IDKeychainTestingFields: @unchecked Sendable {
    let fields: [String: Any]
}
#endif
