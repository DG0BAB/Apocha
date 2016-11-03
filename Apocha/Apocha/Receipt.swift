//
//  Receipt.swift
//  Apocha
//
//  Created by Joachim Deelen on 26.10.16.
//  Copyright © 2016 micabo software UG. All rights reserved.
//

import Foundation

public struct Receipt {
	var bundleIdentifier: String
	var appVersion: String
	var opaqueValue: [UInt8]
	var sha1Hash: [UInt8]
	var inAppPurchaseReceipts: [InAppPurchaseReceipt]?
	var originalApplicationVersion: String;
	var receiptCreationDate: Date
	var receiptExpirationDate: Date
}

public struct InAppPurchaseReceipt {
	var quantity: Int
	var productIdentifier: String
	var transactionIdentifier: String
	var originalTransactionIdentifier: String
	var purchaseDate: Date
	var originalPurchaseDate: Date
	var subscriptionExpirationDate: Date?
	var cancellationDate: Date?
	var appItemId: String?
	var externalVersionIdentifier: String?
	var webOrderLineItemId: Int
}
