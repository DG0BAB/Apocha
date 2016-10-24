//: Playground - noun: a place where people can play

import Cocoa
import Security.SecAsn1Coder


infix operator >>>: LogicalConjunctionPrecedence
public func >>>(result: OSStatus, function: @autoclosure () -> OSStatus) -> OSStatus {
	print(result)
	if result == noErr {
		return function()
	}
	return result
}
let receiptURL = Bundle.main.url(forResource: "receipt_Valid", withExtension: nil)

var rawPayload: Data?


if let receiptURL = receiptURL {
	do {
		let receiptDataPKCS7 = try! Data(contentsOf: receiptURL)
		var itemFormat: SecExternalFormat = .formatPKCS7
		var itemType: SecExternalItemType = .itemTypeUnknown
		var outItems: CFArray?
		var importExportParams: UnsafePointer<SecItemImportExportKeyParameters>?
		let ImpStatus = SecItemImport(receiptDataPKCS7 as CFData, nil, &itemFormat, &itemType, [SecItemImportExportFlags.pemArmour], importExportParams, nil, &outItems)
		
		print(outItems!)
		
		if let items = (outItems as NSArray?), items.count == 3 {
			print(items)
			var cert: SecCertificate = items.object(at: 0) as! SecCertificate
			var error: Unmanaged<CFError>?
			var valueDict: CFDictionary? = SecCertificateCopyValues(cert, nil, &error)
			
			cert = items.object(at: 1) as! SecCertificate
			var valueDict1: CFDictionary? = SecCertificateCopyValues(cert, nil, &error)
		
			cert = (items.object(at: 2) as! SecCertificate)
			var valueDict2: CFDictionary? = SecCertificateCopyValues(cert, nil, &error)
		}
		
		
		
		
		let basicX509Policy: SecPolicy = SecPolicyCreateBasicX509();
		var decoder: CMSDecoder?
		var content: CFData?
		var numberOfSigners: Int = 0
		var signerStatus: CMSSignerStatus = .unsigned
		var certificateVirificationStatus: OSStatus = noErr
		
		var bytes: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer.allocate(capacity: receiptDataPKCS7.count)
		receiptDataPKCS7.copyBytes(to: bytes, count: receiptDataPKCS7.count)
		
		let status = CMSDecoderCreate(&decoder)
			>>> CMSDecoderUpdateMessage(decoder!, bytes, receiptDataPKCS7.count)
			>>> CMSDecoderFinalizeMessage(decoder!)
			>>> CMSDecoderCopyContent(decoder!, &content)
			>>> CMSDecoderGetNumSigners(decoder!, &numberOfSigners)
			>>> CMSDecoderCopySignerStatus(decoder!, 0, basicX509Policy, true, &signerStatus, nil, &certificateVirificationStatus)
		
		print("Status \(status) Number of Signers: \(numberOfSigners) Signer Status: \(signerStatus.rawValue) Certificate: \(certificateVirificationStatus)")
		if let content = content {
			print("Content \(content)")
			rawPayload = Data()
			rawPayload?.append(content as Data)
		}
	}
	
	
}

// This defines one Attribute of the Payload
struct ReceiptAttribute {
	var type: SecAsn1Item		// INTEGER
	var version: SecAsn1Item	// INTEGER
	var value: SecAsn1Item		// OCTET STRING
}

struct ReceiptAttributes {
	var attributes: UnsafeMutableBufferPointer<ReceiptAttribute> 		// RVReceiptAttribute **attrs;
}

let sizeofAsn1Data = UInt32(MemoryLayout<SecAsn1Item>.stride)
let sizeofReceiptAttribute = UInt32(MemoryLayout<ReceiptAttribute>.stride)
let sizeofReceiptAttributes = MemoryLayout<UnsafeMutablePointer<ReceiptAttribute>>.stride

MemoryLayout<SecAsn1Item>.alignment
MemoryLayout<ReceiptAttribute>.alignment
MemoryLayout<ReceiptAttributes>.alignment

var sub: Void? = nil

let oneReceiptAttributeTemplate: [SecAsn1Template] = [
	SecAsn1Template(kind: UInt32(SEC_ASN1_SEQUENCE), offset: 0, sub: &sub, size: sizeofReceiptAttribute),
	SecAsn1Template(kind: UInt32(SEC_ASN1_INTEGER), offset: 0, sub: &sub, size: 0),
	SecAsn1Template(kind: UInt32(SEC_ASN1_INTEGER), offset: sizeofAsn1Data, sub: &sub, size: 0),
	SecAsn1Template(kind: UInt32(SEC_ASN1_OCTET_STRING), offset: sizeofAsn1Data*2, sub: &sub, size: 0),
	SecAsn1Template(kind: 0, offset: 0, sub: &sub, size: 0),
]

oneReceiptAttributeTemplate
UInt32(MemoryLayout<SecAsn1Template>.stride)

UInt32(MemoryLayout.size(ofValue: oneReceiptAttributeTemplate))

let receiptAttributeTemplate: [SecAsn1Template] = [
	SecAsn1Template(kind: UInt32(SEC_ASN1_SET | SEC_ASN1_GROUP), offset: 0, sub: oneReceiptAttributeTemplate, size: UInt32(MemoryLayout.stride(ofValue: oneReceiptAttributeTemplate))),
	SecAsn1Template(kind: 0, offset: 0, sub: &sub, size: 0),
]

receiptAttributeTemplate

if let rawPayload = rawPayload {
	var asn1Decoder: SecAsn1CoderRef?
	// Create the ASN.1 parser
	var status = SecAsn1CoderCreate(&asn1Decoder)
	var attributes: UnsafePointer<UnsafePointer<ReceiptAttribute>>?
	var payloadBytes: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer.allocate(capacity: rawPayload.count)
	rawPayload.copyBytes(to: payloadBytes, count: rawPayload.count)

	status = SecAsn1Decode(asn1Decoder!, payloadBytes, rawPayload.count, receiptAttributeTemplate, &attributes)
	
	attributes
	attributes?.pointee.pointee

	var index = 0
	while attributes?.advanced(by: index).pointee != nil {
		if let item: ReceiptAttribute = attributes?.advanced(by: index).pointee.pointee {
			print("Type: \(item.type.Data.pointee)")
			print("Version: \(item.version.Data.pointee)")
			for pos in 0 ..< item.value.Length {
				print("Data: \(item.value.Data.advanced(by: pos).pointee)")
				
			}
		}
		index += 1
	}
	
}

