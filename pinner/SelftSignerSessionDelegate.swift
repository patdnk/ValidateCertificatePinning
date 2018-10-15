//
//  SelftSignerSessionDelegate.swift
//  pinner
//
//  Created by Ricardo Maqueda Martinez on 14/10/2018.
//  Copyright © 2018 Infinum. All rights reserved.
//

import UIKit
import Alamofire

class SelftSignerSessionDelegate: SessionDelegate {
    
    override init() {
        super.init()
        
//        sessionDidReceiveChallengeWithCompletion = { session, challenge, completion in
//            guard let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0 else {
//                completion(.cancelAuthenticationChallenge, nil)
//                return
//            }
//
//            completion(.useCredential, URLCredential(trust: trust))
//        }
    }

    override func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        guard let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0 else {
            // This case will probably get handled by ATS, but still...
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: trust))
    }
    
}
