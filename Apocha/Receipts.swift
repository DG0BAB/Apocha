//
//  Receipts.swift
//  Apocha
//
//  Created by Joachim Deelen on 26.10.16.
//  Copyright © 2016 micabo software UG. All rights reserved.
//

import Foundation

// MARK: - Receipt

/** A Receipt provides all the receipt fields for an App-Receipt.
It bundles all the Receipt Fields from the payload of the receipt file
that was created during the purchase of an App from the MacApp Store or
during an In-App-Purchase. If the Receipt is from an In-App-Purchase, the
property `inAppPurchaseReceipts` holds the corresponding Receipt Fields.

**See also:**
[Receipt Validation Programming Guide - Receipt Fields](https://developer.apple.com/library/content/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html#//apple_ref/doc/uid/TP40010573-CH106-SW1)
*/
public struct Receipt {
	/// The app’s bundle identifier.
	/// This corresponds to the value of CFBundleIdentifier in the Info.plist file.
	let bundleIdentifier: String
	
	/// The app’s version number.
	/// This corresponds to the value of CFBundleVersion (in iOS) or CFBundleShortVersionString (in OS X) in the Info.plist.
	let appVersion: String
	
	/// An opaque value used, with other data, to compute the SHA-1 hash during validation.
	let opaqueValue: Data
	
	///A SHA-1 hash, used to validate the receipt.
	let sha1Hash: Data
	
	/** An Array with in-app purchase receipts.
	
	**From the Receipt Validation Programming Guide:**
	
	The in-app purchase receipt for a consumable product is added to the receipt when the purchase is made.
	It is kept in the receipt until your app finishes that transaction. After that point, it is removed from
	the receipt the next time the receipt is updated—for example, when the user makes another purchase or if
	your app explicitly refreshes the receipt.

	The in-app purchase receipt for a non-consumable product, auto-renewable subscription, non-renewing
	subscription, or free subscription remains in the receipt indefinitely.
	*/
	let inAppPurchaseReceipts: [InAppPurchaseReceipt]?
	
	/// The version of the app that was originally purchased.
	/// This corresponds to the value of CFBundleVersion (in iOS) or CFBundleShortVersionString (in OS X) in the
	/// Info.plist file when the purchase was originally made.
	///	In the sandbox environment, the value of this field is always “1.0”.
	let originalApplicationVersion: String;
	
	/** The date when the app receipt was created.
	When validating a receipt, use this date to validate the receipt’s signature.
	
	- note: *From the Receipt Validation Programming Guide:*
	
	Many cryptographic libraries default to using the device’s current time and date when validating a pkcs7 package,
	but this may not produce the correct results when validating a receipt’s signature. For example, if the receipt was
	signed with a valid certificate, but the certificate has since expired, using the device’s current date incorrectly
	returns an invalid result. Therefore, make sure your app always uses the date from the Receipt Creation Date field to
	validate the receipt’s signature.
	*/
	let receiptCreationDate: Date
	
	/// The date that the app receipt expires.
	/// This key is present only for apps purchased through the Volume Purchase Program. If this key is not present,
	/// the receipt does not expire. When validating a receipt, compare this date to the current date to determine whether
	/// the receipt is expired. Do not try to use this date to calculate any other information, such as the time remaining
	/// before expiration.
	let receiptExpirationDate: Date?
}


// MARK: - InAppPurchaseReceipt

public struct InAppPurchaseReceipt {
	let quantity: Int
	let productIdentifier: String
	let transactionIdentifier: String
	let originalTransactionIdentifier: String
	let purchaseDate: Date
	let originalPurchaseDate: Date
	let subscriptionExpirationDate: Date?
	let cancellationDate: Date?
	let appItemId: String?
	let externalVersionIdentifier: String?
	let webOrderLineItemId: Int?
}


// MARK: - Custom Operator
infix operator >>>: LogicalConjunctionPrecedence

/// Conjunction Operator to chain calls together that return an OSStatus Value
private func >>>(result: OSStatus, function: @autoclosure () -> OSStatus) -> OSStatus {
	if result == noErr {
		return function()
	}
	return result
}


// MARK: - RawReceipt

/**
A RawReceipt contains the encrypted data of the Receipt exactly how it is stored
at a given URL. A RawReceipt is initialized with an URL. During initialization,
the receipt is read amd contents are stored within an internal Buffer of type Data.

Use the decode function to decrypt the RwaReceipt into a DecodedReceipt
*/
open class RawReceipt {
	
	private let url: URL
	private let data: Data
	
	/** Initialize a RawReceipt with the contents of a receipt at a given URL
	- parameter url:The URL of the receipt
	- throws: ApochaError.invalidReceipt In case there is no receipt at the given
	URL or the receipt can not be read.
	*/
	public init(url: URL) throws {
		do {
			data = try Data(contentsOf: url)
			self.url = url
		} catch let error {
			throw ApochaError.invalidReceiptURL(error)
		}
	}
	
	/** Decode the receipt and create a DecodedReceipt out of it.
	- throws: ApochaError.decodingReceipt(DecodingFailures)
	- returns: DecodedReceipt
	*/
	public func decode() throws -> DecodedReceipt {
		var itemFormat: SecExternalFormat = .formatPKCS7
		var itemType: SecExternalItemType = .itemTypeUnknown
		var outItems: CFArray?
		let importStatus = SecItemImport(data as CFData, nil, &itemFormat, &itemType, [SecItemImportExportFlags.pemArmour], nil, nil, &outItems)
		
		guard let certificates = outItems as? [SecCertificate], importStatus == noErr, certificates.count == 3  else {
			throw ApochaError.decodingReceipt(.retrievingCertificates)
		}
		
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
			throw ApochaError.decodingReceipt(.retrievingPayload)
		}
		return DecodedReceipt(certificates: certificates, payload: payload, numSigners: numberOfSigners, signerStatus: signerStatus, certVerificationStatus: CSSM_TP_CERTVERIFY_STATUS(certificateVerificationStatus))
	}
}


// MARK: - Decoded Receipt

/** A DecodedReceipt contains the decrypted data of a RawReceipt.

Create a DecodedReceipt by calling the decode function of a RawReceipt.
Then check the desired values, like certificates, signerStatus, numSigners
in your application code if they match what you expect. Try to obfuscate these
checks as good as possible.
*/
public struct DecodedReceipt {
	
	/// The Certificates used to sign this receipt
	public let certificates: [SecCertificate]?
	
	/// The number of certificates used to sign the receipt
	public var numCertificates: Int {
		guard let num = certificates?.count else { return 0 }
		return num
	}
	
	/// The number of signers. Check, if it matches the expected number of signers
	public let numSigners: Int
	
	/// Signer Status. Check if this matches the desired status.
	public let signerStatus: CMSSignerStatus
	
	/// The verifications status of the certificates. Check, if this matches the disired status.
	public let certVerificationStatus: CSSM_TP_CERTVERIFY_STATUS
	
	private let payload: Data?
	
	/** Initialzes a DecodedReceipt with the given values.
	- parameters:
		- certificates: An array with certificates
		- payload: The encrypted raw payload of the receipt
		- numSigners: The number of signers. Default = 0
		- signerStatus: The signer status. Default is .unsigned
		- certVerificationStatus: The status of the certificate verification. Default = CSSM_TP_CERTVERIFY_UNKNOWN
	*/
	public init(certificates: [SecCertificate], payload: Data, numSigners: Int = 0, signerStatus: CMSSignerStatus = .unsigned, certVerificationStatus: CSSM_TP_CERTVERIFY_STATUS = CSSM_TP_CERTVERIFY_STATUS(CSSM_TP_CERTVERIFY_UNKNOWN)) {
		self.certificates = certificates
		self.payload = payload
		self.numSigners = numSigners
		self.signerStatus = signerStatus
		self.certVerificationStatus = certVerificationStatus
	}
	
	/** Retrieves the values for the given certificate. The values are returned as
	a nested dictionary.
	- parameter certificate: Certificate of type SecCertificate to get the values from
	- throws: ApochaError.retrievingCertificateValues(Error)
	- returns: A dictionary of type [String : Any]
	*/
	public func valuesFromCertificate(_ certificate: SecCertificate) throws -> [String : Any]? {
		var error: Unmanaged<CFError>?
		guard let result = SecCertificateCopyValues(certificate, nil, &error) as? [String : Any] else {
			throw ApochaError.retrievingCertificateValues(error as! Error)
		}
		return result
	}
	
	/** The Receipt with all the values that you might be interested in
	and that you should use withinh your App. Actually this is the
	decrypted payload of this DecodedReceipt. The returned Receipt holds
	all the properties as descriped in the section Receipt Fields of the
	Receipt Validation Programming Guide.

	**See also:**
	[Receipt Validation Programming Guide - Receipt Fields](https://developer.apple.com/library/content/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html#//apple_ref/doc/uid/TP40010573-CH106-SW1)
	*/
	public lazy var receipt: Receipt? = {
		guard let payload = self.payload else { return nil }
		return Receipt(payload: payload)
	}()
	
}
