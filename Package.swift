// swift-tools-version:4.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Scrypt",
    products: [
        .library(
            name: "Scrypt",
            targets: ["libscrypt", "Scrypt"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "libscrypt",
            dependencies: [],
            path: "libscrypt"
        ),
        .target(
            name: "Scrypt",
            dependencies: ["libscrypt"]),
        .testTarget(
            name: "ScryptTests",
            dependencies: ["libscrypt", "Scrypt"]),
    ]
)
