import Foundation

/// SDK release, aligned with `@last1id/sdk` 0.4.
public enum Last1IDVersion {
    public static let current = "0.4.0"

    /// Product token only. No device, user, or token data.
    public static let userAgent = "Last1ID-Swift/\(current)"
}
