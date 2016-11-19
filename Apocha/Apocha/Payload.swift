//
//  Payload.swift
//  Apocha
//
//  Created by Joachim Deelen on 08.11.16.
//  Copyright © 2016 micabo software UG. All rights reserved.
//

import Foundation
import Security.SecAsn1Coder

private protocol PayloadInitializable {
	init?(payload: Data)
}

extension Receipt: PayloadInitializable {
	init?(payload: Data) {

		// Fail, if the payload can't be decoded
		guard let values = PayloadDecoder(payload: payload)?.values else { return nil }
		
		let inAppPuchaseReceipts: [InAppPurchaseReceipt]?

		// If there are In-App purchase receipts within the payload, create
		// an array of them now.
		if let inAppPurchaseData = values[ASNField.ASNFieldType.inAppPurchaseReceipt] as? [Data] {
			inAppPuchaseReceipts = []
			for oneInAppPurchaseData in inAppPurchaseData {
				if let inAppPuchaseReceipt = InAppPurchaseReceipt(payload: oneInAppPurchaseData) {
					inAppPuchaseReceipts?.append(inAppPuchaseReceipt)
				}
			}
		} else {
			inAppPuchaseReceipts = nil
		}
		
		// Fail, if one or more of the required fields are missing in the values-dict
		guard let bundleIdentifier = values[ASNField.ASNFieldType.bundleIdentifier] as? String,
				let appVersion = values[ASNField.ASNFieldType.appVersion] as? String,
				let opaqueValue = values[ASNField.ASNFieldType.opaqueValue] as? Data,
				let sha1Hash = values[ASNField.ASNFieldType.sha1Hash] as? Data,
				let originalApplicationVersion = values[ASNField.ASNFieldType.originalApplicationVersion] as? String,
				let receiptCreationDate = values[ASNField.ASNFieldType.receiptCreationDate] as? Date else { return nil }
		
		self.init(bundleIdentifier: bundleIdentifier,
		          appVersion: appVersion,
		          opaqueValue: opaqueValue,
		          sha1Hash: sha1Hash,
		          inAppPurchaseReceipts: inAppPuchaseReceipts,
		          originalApplicationVersion: originalApplicationVersion,
		          receiptCreationDate: receiptCreationDate,
		          receiptExpirationDate: values[ASNField.ASNFieldType.receiptExpirationDate] as? Date)
	}
}

extension InAppPurchaseReceipt: PayloadInitializable {
	init?(payload: Data) {
		
		guard let values = PayloadDecoder(payload: payload)?.values else { return nil }
		
		guard let quantity = values[ASNField.ASNFieldType.quatity] as? Int,
			let productIdentifier = values[ASNField.ASNFieldType.productIdentifier] as? String,
			let transactionIdentifier = values[ASNField.ASNFieldType.transactionIdentifier] as? String,
			let originalTransactionIdentifier = values[ASNField.ASNFieldType.originalTransactionIdentifier] as? String,
			let purchaseDate = values[ASNField.ASNFieldType.purchaseDate] as? Date,
			let originalPurchaseDate = values[ASNField.ASNFieldType.originalPurchaseDate] as? Date else { return nil }
		
		self.init(quantity: quantity,
		          productIdentifier: productIdentifier,
		          transactionIdentifier: transactionIdentifier,
		          originalTransactionIdentifier: originalTransactionIdentifier,
		          purchaseDate: purchaseDate,
		          originalPurchaseDate: originalPurchaseDate,
		          subscriptionExpirationDate: values[ASNField.ASNFieldType.subscriptionExpirationDate] as? Date,
		          cancellationDate: values[ASNField.ASNFieldType.cancellationDate] as? Date,
		          appItemId: nil,
		          externalVersionIdentifier: nil,
		          webOrderLineItemId: values[ASNField.ASNFieldType.webOrderLineItemId] as? Int)
	}
}


// MARK: - Private Stuff 

private extension Dictionary {
	subscript(key: ASNField.ASNFieldType) -> Any? {
		get {
			if let indexForKey = self.index(forKey: key as! Key) {
				return self[indexForKey].value
			}
			return nil
		}
		// Special handling for InAppPurchase receipts
		// Because there can be more than one of them,
		// they are wrapped into an Array before inserted
		// into the dictionary
		set {
			if var value = newValue {
				if case .inAppPurchaseReceipt = key {
					if var arrayValue = self[key] as? [Any] {
						arrayValue.append(value)
						value = arrayValue
					} else {
						value = [value]
					}
				}
				updateValue(value as! Value, forKey: key as! Key)
			} else {
				removeValue(forKey: key as! Key)
			}
		}
	}
}

// This defines one Attribute of the Payload
private struct ReceiptAttribute {
	var type: SecAsn1Item		// INTEGER
	var version: SecAsn1Item		// INTEGER
	var value: SecAsn1Item		// OCTET STRING
}

// Decodes the Payload of a Receipt and stores the corresponding
// values into a Dictionary of type [ASNField.ASNFieldType : Any].
// By using the desired ASNFieldType as the key to the Dictionary,
// the value for a specific field can be accessed.
// Creating an instance of the PayloadDecoder fails, if the given
// Payload can't be decoded.
private class PayloadDecoder: PayloadInitializable {
	
	fileprivate var values: [ASNField.ASNFieldType : Any] = [:]
	
	private let sizeofAsn1Data = UInt32(MemoryLayout<SecAsn1Item>.stride)
	private let sizeofReceiptAttribute = UInt32(MemoryLayout<ReceiptAttribute>.stride)
	private var sub: Void? = nil
	
	required public init?(payload: Data) {
		let oneReceiptAttributeTemplate: [SecAsn1Template] = [
			SecAsn1Template(kind: UInt32(SEC_ASN1_SEQUENCE), offset: 0, sub: &sub, size: sizeofReceiptAttribute),
			SecAsn1Template(kind: UInt32(SEC_ASN1_INTEGER), offset: 0, sub: &sub, size: 0),
			SecAsn1Template(kind: UInt32(SEC_ASN1_INTEGER), offset: sizeofAsn1Data, sub: &sub, size: 0),
			SecAsn1Template(kind: UInt32(SEC_ASN1_OCTET_STRING), offset: sizeofAsn1Data*2, sub: &sub, size: 0),
			SecAsn1Template(kind: 0, offset: 0, sub: &sub, size: 0),
			]
		
		let receiptAttributeSetTemplate: [SecAsn1Template] = [
			SecAsn1Template(kind: UInt32(SEC_ASN1_SET | SEC_ASN1_GROUP), offset: 0, sub: oneReceiptAttributeTemplate, size: UInt32(MemoryLayout.stride(ofValue: oneReceiptAttributeTemplate))),
			SecAsn1Template(kind: 0, offset: 0, sub: &sub, size: 0),
			]
		
		// Create the ASN.1 parser/decoder
		var asn1Decoder: SecAsn1CoderRef?
		var status = SecAsn1CoderCreate(&asn1Decoder)
		
		guard status == noErr else { return nil }
		
		var attributes: UnsafePointer<UnsafePointer<ReceiptAttribute>>?
		let payloadBytes: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer.allocate(capacity: payload.count)
		payload.copyBytes(to: payloadBytes, count: payload.count)
			
		// Decode the Payload
		status = SecAsn1Decode(asn1Decoder!, payloadBytes, payload.count, receiptAttributeSetTemplate, &attributes)

		guard status == noErr else { return nil }

		var index = 0
		while attributes?.advanced(by: index).pointee != nil {
			if let item: ReceiptAttribute = attributes?.advanced(by: index).pointee.pointee {
				if let asnField = ASNField(receiptAttribute: item) {
					values[asnField.fieldType] = asnField.value
				}
			}
			index += 1
		}
	}
}


private extension Int {
	/// Constructs an Int from a series of uint8 bytes
	init(bytes: UnsafeMutablePointer<uint8>, count: Int) {
		var value = Int(bytes.pointee)
		for pos in 1..<count {
			value = value << 8
			value |= Int(bytes.advanced(by: pos).pointee)
		}
		self = value
	}
}

// Transparently decodes different ASN1 Data-Types and stores
// their value. Depending on the concreate Type different
// encoding mechanisms are used. ASNFields are created by initilazing
// them with the associated ReceiptAttribute from the Payload. Field- and
// Value-Type are automatically selected.
// Creating an instance fails, if Field-Type and/or Value-Type or the
// value itself can't be decoded.
private struct ASNField {

	enum ASNFieldType: Int {
		// App Receipt Fields
		case bundleIdentifier = 2, appVersion, opaqueValue, sha1Hash
		case receiptCreationDate = 12
		case inAppPurchaseReceipt = 17
		case originalApplicationVersion = 19
		case receiptExpirationDate = 21
		
		// In-App Purchase Receipt Fields
		case quatity = 1701, productIdentifier, transactionIdentifier, purchaseDate, originalTransactionIdentifier, originalPurchaseDate
		case subscriptionExpirationDate = 1708
		case webOrderLineItemId = 1711, cancellationDate
	}
	
	enum ASNValueType: UInt8 {
		case integer = 0x02
		case data = 0x04
		case utf8String = 0x0c
		case date = 0x16
		case set = 0x31
		
		func value(item: SecAsn1Item) -> Any? {
			if let (bytes, length) = self.decodeLength(item: item) {
				switch self {
				case .integer:
					return Int(bytes: bytes, count: length)
					
				case .data:
					return Data(bytes: UnsafeRawPointer(bytes), count: length)
					
				case .utf8String:
					if let utf8String = String(bytesNoCopy: UnsafeMutableRawPointer(bytes), length: length, encoding: .utf8, freeWhenDone: false) {
						return utf8String
					}
					
				case .date:
					if let ia5String = String(bytesNoCopy: UnsafeMutableRawPointer(bytes), length: length, encoding: .ascii, freeWhenDone: false) {
						return ISO8601DateFormatter().date(from: ia5String)
					}
				case .set:
					return Data(bytes: UnsafeRawPointer(item.Data), count: item.Length)
				}
			}
			return nil
		}
		
		typealias TLVLength = (bytes: UnsafeMutablePointer<uint8>, count: Int)
		
		// ASN1 is encoded as TLV: Type-Length-Value
		func decodeLength(item: SecAsn1Item) -> TLVLength? {
			var result: TLVLength? = nil
			
			if case .data = self  {
				result = TLVLength(bytes: item.Data, count: item.Length)
			} else if let data = item.Data {
				// Get the length
				var length: Int = Int(data.advanced(by: 1).pointee)
				let numberOfLengthBytes: Int
				
				// If Bit 7 of the length is set, then bits 0-6 tells
				// us how many of the following bytes are used to
				// specify the length.
				if length & 0b10000000 == 0b10000000 {
					numberOfLengthBytes = length & 0b01111111
					length = Int(bytes: data.advanced(by: 2), count: numberOfLengthBytes)
				} else {
					numberOfLengthBytes = 0
				}
				result = TLVLength(bytes: data.advanced(by: numberOfLengthBytes+2), count: length)
			}
			return result
		}
	}
	
	fileprivate let fieldType: ASNFieldType
	fileprivate let valueType: ASNValueType
	fileprivate let value: Any
	
	init?(receiptAttribute: ReceiptAttribute) {
		// Fail if fieldType can't be dtermined
		guard let fieldType = ASNFieldType(rawValue: Int(bytes: receiptAttribute.type.Data, count: receiptAttribute.type.Length)) else { return nil }
		
		var tmpValueType = ASNValueType(rawValue: receiptAttribute.value.Data.pointee)
		
		// Some special handling for opaqueValue and sha1Hash because they are not TLV encoded
		if tmpValueType == nil && (fieldType == ASNFieldType.opaqueValue || fieldType == ASNFieldType.sha1Hash) {
			tmpValueType = ASNValueType.data
		}
		// Fail, if ValueType can't be determined
		guard let valueType = tmpValueType else { return nil }
		
		self.fieldType = fieldType
		self.valueType = valueType
		// Fail, if the value itself can't be decoded
		guard let value = valueType.value(item: receiptAttribute.value) else { return nil }
		self.value = value
	}
}
