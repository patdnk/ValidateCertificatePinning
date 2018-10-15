//
//  CustomSessionDelegate.swift
//  pinner
//
//  Created by Adis on 20/09/2017.
//  Copyright © 2017 Infinum. All rights reserved.
//

import UIKit
import Alamofire

class CustomSessionDelegate: SessionDelegate {
    
    var key: SecKey?
    
    // Note that this is the almost the same implementation as in the ViewController.swift
    override init() {
        super.init()
        
        // Alamofire uses a block var here
        sessionDidReceiveChallengeWithCompletion = { session, challenge, completion in
            guard let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0 else {
                // This case will probably get handled by ATS, but still...
                completion(.cancelAuthenticationChallenge, nil)
                return
            }
            
            // Compare the server certificate with our own stored
//            if let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0) {
//                let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
//
//                if CustomSessionDelegate.pinnedCertificates().contains(serverCertificateData) {
//                    completion(.useCredential, URLCredential(trust: trust))
//                    return
//                }
//            }
            
            // Or, compare the public keys
            if let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0),
                let serverCertificateKey = SecCertificateCopyPublicKey(serverCertificate) {
                if let key = self.key {
                    if key == serverCertificateKey {
                        completion(.useCredential, URLCredential(trust: trust))
                        return
                    }
                }
//
//
//                if CustomSessionDelegate.pinnedKeys().contains(serverCertificateKey) {
//                    completion(.useCredential, URLCredential(trust: trust))
//                    return
//                }
            }
            
            completion(.cancelAuthenticationChallenge, nil)
        }
    }
    
//    private static func pinnedCertificates() -> [Data] {
//        var certificates: [Data] = []
//
//        if let pinnedCertificateURL = Bundle.main.url(forResource: "httpbinorg", withExtension: "cer") {
//            do {
//                let pinnedCertificateData = try Data(contentsOf: pinnedCertificateURL)
//                certificates.append(pinnedCertificateData)
//            } catch (_) {
//                // Handle error
//            }
//        }
//
//        return certificates
//    }
//
//    private static func pinnedKeys() -> [SecKey] {
//        var publicKeys: [SecKey] = []
//
//        if let pinnedCertificateURL = Bundle.main.url(forResource: "httpbinorg", withExtension: "cer") {
//            do {
//                let pinnedCertificateData = try Data(contentsOf: pinnedCertificateURL) as CFData
//                if let pinnedCertificate = SecCertificateCreateWithData(nil, pinnedCertificateData), let key = publicKey(for: pinnedCertificate) {
//                    publicKeys.append(key)
//                }
//            } catch (_) {
//                // Handle error
//            }
//        }
//
//        return publicKeys
//    }
    
}
