import XCTest

import ScryptTests

var tests = [XCTestCaseEntry]()
tests += ScryptTests.allTests()
XCTMain(tests)