import Foundation

enum ScryptError: Error {
  case failedToGenerateHash
  case failedToComposeMcf
  case failedToGenerateSalt
  case failedToCheck
}
