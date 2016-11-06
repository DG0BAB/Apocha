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
	let payload: Data?
	let numSigners: Int
	let signerStatus: CMSSignerStatus
	let certVerificationStatus: CSSM_TP_CERTVERIFY_STATUS
	
	init(certificates: [SecCertificate], payload: Data, numSigners: Int = 0, signerStatus: CMSSignerStatus = .unsigned, certVerificationStatus: CSSM_TP_CERTVERIFY_STATUS = CSSM_TP_CERTVERIFY_STATUS(CSSM_TP_CERTVERIFY_UNKNOWN)) {
		self.certificates = certificates
		self.payload = payload
		self.numSigners = numSigners
		self.signerStatus = signerStatus
		self.certVerificationStatus = certVerificationStatus
	}
	
	static func valuesFromCertificate(_ certificate: SecCertificate) -> [String : Any]? {
		var error: Unmanaged<CFError>?
		return SecCertificateCopyValues(certificate, nil, &error) as? [String : Any]
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

open class ReceiptDecoder {
	
	static func decodeReceipt(url receiptURL: URL) throws -> DecodedReceipt? {
		var result: DecodedReceipt?
		do {
			let receiptDataPKCS7 = try Data(contentsOf: receiptURL)
			var itemFormat: SecExternalFormat = .formatPKCS7
			var itemType: SecExternalItemType = .itemTypeUnknown
			var outItems: CFArray?
			let importStatus = SecItemImport(receiptDataPKCS7 as CFData, nil, &itemFormat, &itemType, [SecItemImportExportFlags.pemArmour], nil, nil, &outItems)
			
			if let certificates = outItems as? [SecCertificate], importStatus == noErr, certificates.count == 3 {
				print(outItems!)
				
				let basicX509Policy: SecPolicy = SecPolicyCreateBasicX509()
				var decoder: CMSDecoder?
				var content: CFData?
				var numberOfSigners: Int = 0
				var signerStatus: CMSSignerStatus = .unsigned
				var certificateVerificationStatus: OSStatus = OSStatus(CSSM_TP_CERTVERIFY_STATUS(CSSM_TP_CERTVERIFY_UNKNOWN))
				
				let bytes: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer.allocate(capacity: receiptDataPKCS7.count)
				receiptDataPKCS7.copyBytes(to: bytes, count: receiptDataPKCS7.count)
				
				let status = CMSDecoderCreate(&decoder)
					>>> CMSDecoderUpdateMessage(decoder!, bytes, receiptDataPKCS7.count)
					>>> CMSDecoderFinalizeMessage(decoder!)
					>>> CMSDecoderCopyContent(decoder!, &content)
					>>> CMSDecoderGetNumSigners(decoder!, &numberOfSigners)
					>>> CMSDecoderCopySignerStatus(decoder!, 0, basicX509Policy, true, &signerStatus, nil, &certificateVerificationStatus)
				
				if let payload = content as? Data, status == noErr {
					result = DecodedReceipt(certificates: certificates, payload: payload, numSigners: numberOfSigners, signerStatus: signerStatus, certVerificationStatus: CSSM_TP_CERTVERIFY_STATUS(certificateVerificationStatus))
				}
			}
		} catch let error {
			throw ApochaError.invalidReceiptURL(error)
		}
		return result
	}
}
