//
//  Payload.swift
//  Apocha
//
//  Created by Joachim Deelen on 08.11.16.
//  Copyright © 2016 micabo software UG. All rights reserved.
//

import Foundation

public protocol PayloadInitializeable {
	init(payload: Data)
}

extension Receipt: PayloadInitializeable {
	public init(payload: Data) {
		self.init(bundleIdentifier: "", appVersion: "", opaqueValue: [UInt8(0)], sha1Hash: [], inAppPurchaseReceipts: [], originalApplicationVersion: "", receiptCreationDate: Date(), receiptExpirationDate: Date())
	}
}

extension InAppPurchaseReceipt: PayloadInitializeable {
	public init(payload: Data) {
		self.init(quantity: 0, productIdentifier: "", transactionIdentifier: "", originalTransactionIdentifier: "", purchaseDate: Date(), originalPurchaseDate: Date(), subscriptionExpirationDate: nil, cancellationDate: nil, appItemId: nil, externalVersionIdentifier: nil, webOrderLineItemId: 0)
	}
}
