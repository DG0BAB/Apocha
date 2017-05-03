//
//  SecAsn1CSSM.swift
//  Apocha
//
//  Created by Joachim Deelen on 29.12.16.
//  Copyright © 2016 micabo software UG. All rights reserved.
//

import Foundation

typealias CSSM_SIZE = Int
typealias uint8 = UInt8
struct cssm_data {
	
	public var Length: CSSM_SIZE /* in bytes */
	
	public var Data: UnsafeMutablePointer<uint8>!
	
	public init() {
		Length = 0;
		Data = UnsafeMutablePointer<uint8>.allocate(capacity: 0)
	}
	
	public init(Length: CSSM_SIZE, Data: UnsafeMutablePointer<uint8>!) {
		self.Length = Length
		self.Data = Data
	}
}

typealias SecAsn1Item = cssm_data
typealias SecAsn1CoderRef = OpaquePointer

/*
* An array of these structures defines a BER/DER encoding for an object.
*
* The array usually starts with a dummy entry whose kind is SEC_ASN1_SEQUENCE;
* such an array is terminated with an entry where kind == 0.  (An array
* which consists of a single component does not require a second dummy
* entry -- the array is only searched as long as previous component(s)
* instruct it.)
*/
public struct SecAsn1Template_struct {
	
	/*
	* Kind of item being decoded/encoded, including tags and modifiers.
	*/
	public var kind: UInt32
	
	
	/*
	* This value is the offset from the base of the structure (i.e., the
	* (void *) passed as 'src' to SecAsn1EncodeItem, or the 'dst' argument
	* passed to SecAsn1CoderRef()) to the field that holds the value being
	* decoded/encoded.
	*/
	public var offset: UInt32
	
	
	/*
	* When kind suggests it (e.g., SEC_ASN1_POINTER, SEC_ASN1_GROUP,
	* SEC_ASN1_INLINE, or a component that is *not* a SEC_ASN1_UNIVERSAL),
	* this points to a sub-template for nested encoding/decoding.
	* OR, iff SEC_ASN1_DYNAMIC is set, then this is a pointer to a pointer
	* to a function which will return the appropriate template when called
	* at runtime.  NOTE! that explicit level of indirection, which is
	* necessary because ANSI does not allow you to store a function
	* pointer directly as a "void *" so we must store it separately and
	* dereference it to get at the function pointer itself.
	*/
	public var sub: UnsafeRawPointer
	
	
	/*
	* In the first element of a template array, the value is the size
	* of the structure to allocate when this template is being referenced
	* by another template via SEC_ASN1_POINTER or SEC_ASN1_GROUP.
	* In all other cases, the value is ignored.
	*/
	public var size: UInt32
}
public typealias SecAsn1Template = SecAsn1Template_struct

/*
* Supported import/export Formats
*/
public enum SecExternalFormat : UInt32 {
	
	
	/*
	* When importing: unknown format
	* When exporting: default format for item
	*/
	case formatUnknown
	
	
	/*
	* Public and Private Key formats.
	* Default for export is kSecFormatOpenSSL.
	*/
	case formatOpenSSL /* a.k.a. X509 for public keys */
	
	case formatSSH /* OpenSSH v.1 */
	
	case formatBSAFE
	
	
	/* Symmetric Key Formats */
	case formatRawKey /* raw unformatted key bits; default */
	
	
	/* Formats for wrapped symmetric and private keys */
	case formatWrappedPKCS8
	
	case formatWrappedOpenSSL /* traditional openssl */
	
	case formatWrappedSSH /* OpenSSH v.1 */
	
	case formatWrappedLSH
	
	
	/* Formats for certificates */
	case formatX509Cert /* DER encoded; default */
	
	
	/* Aggregate Types */
	case formatPEMSequence /* sequence of certs and/or keys, implies PEM
	*    armour. Default format for multiple items */
	
	
	case formatPKCS7 /* sequence of certs */
	
	case formatPKCS12 /* set of certs and private keys */
	
	case formatNetscapeCertSequence /* sequence of certs, form netscape-cert-sequence */
	
	
	/* Added in Mac OS X 10.5 */
	case formatSSHv2 /* OpenSSH v.2. Note that OpenSSH v2 private keys
	* are in format kSecFormatOpenSSL or
	* kSecFormatWrappedOpenSSL. */
}

/*
* Indication of basic item type when importing.
*/
public enum SecExternalItemType : UInt32 {
	
	
	case itemTypeUnknown /* caller doesn't know what this is */
	
	case itemTypePrivateKey
	
	case itemTypePublicKey
	
	case itemTypeSessionKey
	
	case itemTypeCertificate
	
	case itemTypeAggregate /* PKCS7, PKCS12, kSecFormatPEMSequence, etc. */
}
