import XCTest
@testable import Apocha

class ApochaTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(Apocha().text, "Hello, World!")
    }


    static var allTests = [
        ("testExample", testExample),
    ]
}
