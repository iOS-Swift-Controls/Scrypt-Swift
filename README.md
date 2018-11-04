# Scrypt-Swift
A Swift wrapper utility around [technion's](https://github.com/technion/libscrypt) `libscrypt` C library.

Scrypt is advanced password hashing algorithm which arguably provides better securiry than similar algorithms such as BCrypt or SHA. 

Scrypt is slow hashing algorithm and provides **CPU** as well as **memory** intense workload while creating a hash, thus preventing brute force attacks at cracking passwords.

## Example usage:
```Swift
import Scrypt

// Generates 64 byte hash with 16 bytes random salt and returns result as MCF composed string for storage.
// MFC string includes hash, salt and other algorithm info. 
let hash: String = try! Scrypt.generateHash(
    password: "Password123!",
    N: Scrypt.N, /* 16384 - main performance modifier CPU & RAM cost */
    r: Scrypt.r, /* 8 - RAM cost */
    p: Scrypt.p /* 1 - CPU cost */
)
```

```Swift
import Scrypt

// More generic function where you can supply custom salt and specify hash length. 
// Return value is Data (bytes of data)
let salt: Data = try! Scrypt.generateSalt(length: 16)
let hash: Data = try! Scrypt.generateHash(
    password: "Password123!",
    salt: salt,
    N: Scrypt.N, /* 16384 - main performance modifier CPU & RAM cost */
    r: Scrypt.r, /* 8 - RAM cost */
    p: Scrypt.p, /* 1 - CPU cost */
    length: 64 /* length of generated hash in bytes */
)
```

`N` is main performance modifier, you can change `r` and `p` if you wish to have different CPU/RAM cost ratio.

## Import to your Swift project

```Swift
let package = Package(
    ...
    dependencies: [
      .package(url: "https://github.com/zen-plus/Scrypt-Swift.git, from: "1.0.0")
    ],
    ...
) 
```