import Security
import XCTest
@testable import Last1ID

final class KeychainStoreTests: XCTestCase {
    private var service = ""

    override func setUp() {
        service = "id.last1.sdk.tests.\(UUID().uuidString)"
    }

    /// Deprecated on macOS so the file-keychain helper can call the legacy
    /// SecKeychain functions without a deprecation warning. XCTest still runs it.
    @available(macOS, deprecated: 10.10)
    func testSaveLoadAndClear() async throws {
        let tokens = Last1IDTokens(
            accessToken: "access-1",
            refreshToken: "refresh-1",
            idToken: "id-1",
            expiresAt: Date(timeIntervalSince1970: 1_700_003_600),
            scope: "openid email"
        )
        #if os(macOS)
        let file = try Last1IDTestingFileKeychain()
        let store = Last1IDKeychainTokenStore(service: service, account: "alpha", testingQueryFields: file.queryFields)
        let beta = Last1IDKeychainTokenStore(service: service, account: "beta", testingQueryFields: file.queryFields)
        let production = Last1IDKeychainTokenStore(service: service, account: "alpha")
        let productionQuery = production.testingBaseQuery()
        XCTAssertEqual(productionQuery[kSecUseDataProtectionKeychain as String] as? Bool, true)
        #else
        let store = Last1IDKeychainTokenStore(service: service, account: "alpha")
        let beta = Last1IDKeychainTokenStore(service: service, account: "beta")
        #endif
        XCTAssertEqual(
            Last1IDKeychainTokenStore.itemAccessibility,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
        )

        do {
            try await store.save(tokens)
        } catch {
            #if !os(macOS)
            try skipIfKeychainHasNoAppIdentifier(error)
            #endif
            throw error
        }
        let loaded = try await store.load()
        XCTAssertEqual(loaded, tokens)
        XCTAssertEqual(tokens.description, "Last1IDTokens(redacted)")
        XCTAssertFalse(tokens.debugDescription.contains("access-1"))
        var dumped = ""
        dump(tokens, to: &dumped)
        XCTAssertFalse(dumped.contains("access-1"))
        XCTAssertFalse(dumped.contains("refresh-1"))
        XCTAssertFalse(dumped.contains("id-1"))

        #if !os(macOS)
        let attributes = try keychainAttributes(account: "alpha")
        XCTAssertEqual(
            attributes[kSecAttrAccessible as String] as? String,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
        )
        #endif

        let other = Last1IDTokens(accessToken: "access-2", refreshToken: "refresh-2")
        try await beta.save(other)
        let loadedAlpha = try await store.load()
        let loadedBeta = try await beta.load()
        XCTAssertEqual(loadedAlpha?.accessToken, "access-1")
        XCTAssertEqual(loadedBeta, other)

        try await store.save(Last1IDTokens(accessToken: "access-3"))
        let replaced = try await store.load()
        XCTAssertEqual(replaced?.accessToken, "access-3")
        try await store.clear()
        let cleared = try await store.load()
        XCTAssertNil(cleared)
        let betaStillThere = try await beta.load()
        XCTAssertEqual(betaStillThere, other)
        try await beta.clear()
    }

    #if !os(macOS)
    /// The iOS package test host is not signed with an app identifier, so
    /// the data protection keychain returns -34018. The macOS run is the
    /// one that executes the round trip.
    private func skipIfKeychainHasNoAppIdentifier(_ error: Error) throws {
        guard case Last1IDError.keychain(let status) = error else { return }
        if status == errSecMissingEntitlement {
            throw XCTSkip("This process has no app identifier, so the Keychain returned \(status). The macOS test run saves, loads, and clears tokens in a file keychain.")
        }
    }

    private func keychainAttributes(account: String) throws -> [String: Any] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let attributes = item as? [String: Any] else {
            XCTFail("keychain attributes unavailable: \(status)")
            return [:]
        }
        return attributes
    }
    #endif
}

#if os(macOS)
/// File keychain for unsigned `swift test`. The data protection keychain
/// returns -34018 without an app identifier. This does not change the
/// user's keychain search list. Queries pass `kSecUseKeychain` and
/// `kSecMatchSearchList` instead. The type is deprecated so the legacy
/// SecKeychain calls inside it do not warn.
@available(macOS, deprecated: 10.10)
final class Last1IDTestingFileKeychain: @unchecked Sendable {
    let queryFields: [String: Any]
    private let reference: SecKeychain

    init() throws {
        SecKeychainSetUserInteractionAllowed(false)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("last1id-test-\(UUID().uuidString).keychain")
        try? FileManager.default.removeItem(at: url)

        var access: SecAccess?
        SecAccessCreate("Last1ID tests" as CFString, nil, &access)

        var created: SecKeychain?
        let password = Data("last1id-test".utf8)
        let status = password.withUnsafeBytes { raw in
            SecKeychainCreate(
                url.path,
                UInt32(password.count),
                raw.baseAddress,
                false,
                access,
                &created
            )
        }
        guard status == errSecSuccess, let created else {
            throw Last1IDError.keychain(status)
        }
        let unlock = password.withUnsafeBytes { raw in
            SecKeychainUnlock(created, UInt32(password.count), raw.baseAddress, true)
        }
        if unlock != errSecSuccess {
            SecKeychainDelete(created)
            throw Last1IDError.keychain(unlock)
        }
        reference = created
        queryFields = [
            kSecUseKeychain as String: created,
            kSecMatchSearchList as String: [created] as CFArray,
            kSecUseDataProtectionKeychain as String: false,
        ]
    }

    deinit {
        SecKeychainDelete(reference)
    }
}
#endif
