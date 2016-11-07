//
//  ReceiptDecoder.swift
//  Apocha
//
//  Created by Joachim Deelen on 05.11.16.
//  Copyright © 2016 micabo software UG. All rights reserved.
//

import Foundation

public struct DecodedReceipt {
	
	let certificates: [SecCertificate]?
	var numCertificates: Int {
		guard let num = certificates?.count else { return 0 }
		return num
	}
	let numSigners: Int
	let signerStatus: CMSSignerStatus
	let certVerificationStatus: CSSM_TP_CERTVERIFY_STATUS
	let payload: Data?
	
	init(certificates: [SecCertificate], payload: Data, numSigners: Int = 0, signerStatus: CMSSignerStatus = .unsigned, certVerificationStatus: CSSM_TP_CERTVERIFY_STATUS = CSSM_TP_CERTVERIFY_STATUS(CSSM_TP_CERTVERIFY_UNKNOWN)) {
		self.certificates = certificates
		self.payload = payload
		self.numSigners = numSigners
		self.signerStatus = signerStatus
		self.certVerificationStatus = certVerificationStatus
	}
	
	func valuesFromCertificate(_ certificate: SecCertificate) throws -> [String : Any]? {
		var error: Unmanaged<CFError>?
		guard let result = SecCertificateCopyValues(certificate, nil, &error) as? [String : Any] else {
			throw ApochaError.retrievingCertificateValues(error as! Error)
		}
		return result
	}
	
	var receipt: Receipt? {
		return nil
	}
}

infix operator >>>: LogicalConjunctionPrecedence

private func >>>(result: OSStatus, function: @autoclosure () -> OSStatus) -> OSStatus {
	print(result)
	if result == noErr {
		return function()
	}
	return result
}

open class RawReceipt {
	
	let url: URL
	let data: Data
	
	init(url: URL) throws {
		do {
			data = try Data(contentsOf: url)
			self.url = url
		} catch let error {
			throw ApochaError.invalidReceiptURL(error)
		}
	}
	
	func decode() throws -> DecodedReceipt {
		var itemFormat: SecExternalFormat = .formatPKCS7
		var itemType: SecExternalItemType = .itemTypeUnknown
		var outItems: CFArray?
		let importStatus = SecItemImport(data as CFData, nil, &itemFormat, &itemType, [SecItemImportExportFlags.pemArmour], nil, nil, &outItems)
			
		guard let certificates = outItems as? [SecCertificate], importStatus == noErr, certificates.count == 3  else {
			throw ApochaError.decodingReceipt
		}
		print(outItems!)
				
		let basicX509Policy: SecPolicy = SecPolicyCreateBasicX509()
		var decoder: CMSDecoder?
		var content: CFData?
		var numberOfSigners: Int = 0
		var signerStatus: CMSSignerStatus = .unsigned
		var certificateVerificationStatus: OSStatus = OSStatus(CSSM_TP_CERTVERIFY_STATUS(CSSM_TP_CERTVERIFY_UNKNOWN))
			
		let bytes: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer.allocate(capacity: data.count)
		data.copyBytes(to: bytes, count: data.count)
			
		let status = CMSDecoderCreate(&decoder)
			>>> CMSDecoderUpdateMessage(decoder!, bytes, data.count)
			>>> CMSDecoderFinalizeMessage(decoder!)
			>>> CMSDecoderCopyContent(decoder!, &content)
			>>> CMSDecoderGetNumSigners(decoder!, &numberOfSigners)
			>>> CMSDecoderCopySignerStatus(decoder!, 0, basicX509Policy, true, &signerStatus, nil, &certificateVerificationStatus)
			
		guard let payload = content as? Data, status == noErr else {
			throw ApochaError.decodingReceipt
		}
		return DecodedReceipt(certificates: certificates, payload: payload, numSigners: numberOfSigners, signerStatus: signerStatus, certVerificationStatus: CSSM_TP_CERTVERIFY_STATUS(certificateVerificationStatus))
	}
}
