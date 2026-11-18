// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "Last1ID",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "Last1ID", targets: ["Last1ID"]),
    ],
    targets: [
        .target(
            name: "Last1ID",
            path: "Sources/Last1ID",
            resources: [
                .copy("PrivacyInfo.xcprivacy"),
            ]
        ),
        .testTarget(
            name: "Last1IDTests",
            dependencies: ["Last1ID"],
            path: "Tests/Last1IDTests"
        ),
    ]
)
