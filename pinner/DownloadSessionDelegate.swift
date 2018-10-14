//
//  DownloadSessionDelegate.swift
//  pinner
//
//  Created by Ricardo Maqueda Martinez on 14/10/2018.
//  Copyright © 2018 Infinum. All rights reserved.
//

import UIKit
import Alamofire

class DownloadSessionDelegate: SessionDelegate {
    
    override init() {
        super.init()
        
        sessionDidReceiveChallengeWithCompletion = { session, challenge, completion in
            guard let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0 else {
                completion(.cancelAuthenticationChallenge, nil)
                return
            }
            
            if let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0), let serverCertificateKey = self.publicKey(for: serverCertificate) {
                // TODO: Convert and save public key
                print(serverCertificateKey)
                completion(.useCredential, URLCredential(trust: trust))
            }
            
            completion(.cancelAuthenticationChallenge, nil)
        }
    }
    
    
    private func publicKey(for certificate: SecCertificate) -> SecKey? {
        var publicKey: SecKey?
        
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let trustCreationStatus = SecTrustCreateWithCertificates(certificate, policy, &trust)
        
        if let trust = trust, trustCreationStatus == errSecSuccess {
            publicKey = SecTrustCopyPublicKey(trust)
        }
        
        return publicKey
    }
    
}
