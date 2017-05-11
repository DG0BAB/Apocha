//
//  Error.swift
//  Apocha
//
//  Created by Joachim Deelen on 06.11.16.
//  Copyright © 2016 micabo software UG. All rights reserved.
//

import Foundation

public enum ApochaError: Error {
	case invalidReceiptURL(Error)
	case decodingReceipt(DecodingFailures)
	case retrievingCertificateValues(Error)
	
	public enum DecodingFailures {
		case retrievingCertificates
		case retrievingPayload
	}
}
