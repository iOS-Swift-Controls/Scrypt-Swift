import XCTest
@testable import Scrypt

final class ScryptTests: XCTestCase {
    func testGenerateHash() {
        let hash = try! Scrypt.generateHash(
          password: "abc",
          N: Scrypt.N,
          r: Scrypt.r,
          p: Scrypt.p
      )
      
      
      XCTAssertLessThan(hash.count, Scrypt.MCF_LEN)
      XCTAssertGreaterThan(hash.count, 0)
    }
  
  func generateHash2() {
    let salt: Data = try! Scrypt.generateSalt(length: 16)
    let hash: Data = try! Scrypt.generateHash(
      password: "Password123!",
      salt: salt,
      N: Scrypt.N,
      r: Scrypt.r,
      p: Scrypt.p,
      length: 64
    )

  }

    static var allTests = [
        ("testGenerateHash", testGenerateHash),
    ]
}
