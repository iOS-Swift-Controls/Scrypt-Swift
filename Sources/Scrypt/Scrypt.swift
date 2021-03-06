import Foundation
import libscrypt

/**
 Scrypt Swift wrapper utility for hashing password
 
 Based on technion libscrypt C library: https://github.com/technion/libscrypt
 
 - Common parameters
		- N: CPU AND RAM cost (first modifier). It is main performance modifier with suggested value 16384.
		- r: RAM Cost
		- p: CPU cost (parallelisation)
 
 Standard values of r and p are 8 and 1. They can be changed to modify CPU/RAM ratio
 
 */

public struct Scrypt {
	public static let HASH_LEN = 64
	public static let SAFE_N = 30
	public static let SALT_LEN = 16
	public static let MCF_LEN = 128
	public static let MCF_ID = "$s1"
	public static let N = 16384
	public static let r = 128
	public static let p = 1
	
	public enum Err: Error {
		case failedToGenerateHash
		case failedToComposeMcf
		case failedToGenerateSalt
		case failedToCheck
		case invalidPassword
	}
	
	/**
	 Generates Scrypt hash for given password and salt
	 - Parameters
			- password: password as String value
			- salt: salt as Data value
			- N, r, p: see common parameters
	 - Return value
			Generated scrypt hash as Data with length bytes
	*/
	public static func generateHash(password: String, salt: Data, N: Int, r: Int, p: Int, length: Int) throws -> Data {
		let passwordData = password.data(using: .utf8)!
		return try generateHash(passwordData: passwordData, salt: salt, N: N, r: r, p: p, length: length)
	}

	/**
	 Generates Scrypt hash for given password and salt
	 - Parameters
	 - password: password as Data value
	 - salt: salt as Data value
	 - N, r, p: see common parameters
	 - Return value
	 Generated scrypt hash as Data with length bytes
	 */
	public static func generateHash(passwordData: Data, salt: Data, N: Int, r: Int, p: Int, length: Int) throws -> Data {
		let passwordPtr = passwordData.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
			return ptr
		}
		let saltPtr = salt.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
			return ptr
		}
		
		let hashPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: length)
		let result = libscrypt_scrypt(passwordPtr, passwordData.count, saltPtr, salt.count, UInt64(N), UInt32(r), UInt32(p), hashPtr, length)
		if result < 0 {
			throw Err.failedToGenerateHash
		}
		let hash = Data(bytes: hashPtr, count: length)
		hashPtr.deallocate()
		return hash
	}
	
	/**
	 Generates Scrypt mfc string hash for given password. It generates random salt with default length of 16 bytes.
	 - Parameters
			- password: password as Data value
			- N, r, p: see common parameters
	 - Return value
			Generated scrypt hash as Data with length bytes
	 
	 Length of MCF string is calculated like this:
	 $s1 Identifier, three chars
	 $0e0810 Work order and separator, six chars
	 Formula for binary to base64 length = ceil(n/3)*4
	 $pcL+DWle903AXcKJVwMffA== Salt is 16 bytes, or 24 in Base64
	 $dn+9ujljVc5JTJMC2fYu1ZEHdJyqYkOurmcrBQbMHUfnD6qxbTmNiR075ohNBZjvp66E2aV1pfOrmyNHUefjMg== Hash is 64 bytes, or 88 in Base64.
	 Work order, salt and hash have separators (3)
	 3 + 6 + 24 + 88 + 3 + null byte = 125
	 This is rounded up to a multiple of four for alignment
	 */
	public static func generateHash(password: String, N: Int, r: Int, p: Int) throws -> String {
		let passwordPtr = password.withCString { (ptr: UnsafePointer<Int8>) -> UnsafePointer<Int8> in
			return ptr
		}
		let hashPtr = UnsafeMutablePointer<Int8>.allocate(capacity: MCF_LEN)
		let result = libscrypt_hash(hashPtr, passwordPtr, UInt32(N), UInt8(r), UInt8(p))
		if result == 0 {
			throw Err.failedToGenerateHash
		}
		let hashStr = String(cString: hashPtr)
		hashPtr.deallocate()
		return hashStr
	}
	
	/**
	 Converts hash data into MFC format for storage
	 - Parameters
			- N, r, p: see common parameters
			- salt: salt as base64 encoded string
			- hash: hash as base64 encpded string
		- Return value
			Hash data as string in mfc format
	 
	 Length of MCF string is calculated like this:
	 $s1 Identifier, three chars
	 $0e0810 Work order and separator, six chars
	 Formula for binary to base64 length = ceil(n/3)*4
	 $pcL+DWle903AXcKJVwMffA== Salt is 16 bytes, or 24 in Base64
	 $dn+9ujljVc5JTJMC2fYu1ZEHdJyqYkOurmcrBQbMHUfnD6qxbTmNiR075ohNBZjvp66E2aV1pfOrmyNHUefjMg== Hash is 64 bytes, or 88 in Base64.
	 Work order, salt and hash have separators (3)
	 3 + 6 + 24 + 88 + 3 + null byte = 125
	 This is rounded up to a multiple of four for alignment
	 */
	public static func mcf(N: Int, r: Int, p: Int, salt: String, hash: String) throws -> String {
		let saltPtr = salt.withCString { (ptr: UnsafePointer<Int8>) -> UnsafePointer<Int8> in
			return ptr
		}
		let hashPtr = hash.withCString { (ptr: UnsafePointer<Int8>) -> UnsafePointer<Int8> in
			return ptr
		}
		
		let mcfPtr = UnsafeMutablePointer<Int8>.allocate(capacity: MCF_LEN)
		let result = libscrypt_mcf(UInt32(N), UInt32(r), UInt32(p), saltPtr, hashPtr, mcfPtr)
		if result < 0 {
			throw Err.failedToComposeMcf
		}
		let mcfStr = String(cString: mcfPtr)
		mcfPtr.deallocate()
		return mcfStr
	}

	/**
	 Generates random salt of length bytes. Uses /dev/urandom/
	 - Parameters
			- length: salt length
	 - Return value
			- Salt as byte Data
	 */
	public static func generateSalt(length: Int) throws -> Data {
		let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: length)
		let result = libscrypt_salt_gen(ptr, length)
		if result < 0 {
			throw Err.failedToGenerateSalt
		}
		let salt = Data(bytes: ptr, count: length)
		ptr.deallocate()
		return salt
	}
	
	/**
	 Verifies given hash data in MFC format against password
	 - Parameters
			- mfc: hash data in MFC string format
			- password: password
	 - Return value
			- True if password matches and False otherwise
	 */
	public static func check(mcf: String, password: String) throws -> Bool {
		let passwordPtr = password.withCString { (ptr: UnsafePointer<Int8>) -> UnsafePointer<Int8> in
			return ptr
		}
		var mcfData = mcf.data(using: .utf8)!
		let result = mcfData.withUnsafeMutableBytes { (ptr: UnsafeMutablePointer<Int8>) -> Int32 in
			return libscrypt_check(ptr, passwordPtr)
		}
		if result < 0 {
			throw Err.failedToCheck
		}
		return result == 1
	}

	public static func matchPassword(password: Data, salt: Data, hash: Data, N: Int, r: Int, p: Int, length: Int) throws {
		let passwordPtr = password.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
			return ptr
		}
		let saltPtr = salt.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
			return ptr
		}
		
		let newHashPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: length)
		let result = libscrypt_scrypt(passwordPtr, password.count, saltPtr, salt.count, UInt64(N), UInt32(r), UInt32(p), newHashPtr, length)
		if result < 0 {
			throw Err.failedToGenerateHash
		}
		let newHash = Data(bytes: newHashPtr, count: length)
		newHashPtr.deallocate()
		
		guard newHash == hash else {
			throw Err.invalidPassword
		}
	}
}
