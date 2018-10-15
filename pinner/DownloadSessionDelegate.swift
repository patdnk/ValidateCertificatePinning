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
            
            if let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0) {
                let data = SecCertificateCopyData(serverCertificate) as Data
                self.save(data: data)
                GPCertUtils.dump()
                
                completion(.useCredential, URLCredential(trust: trust))
                return
            }
            
            completion(.cancelAuthenticationChallenge, nil)
        }
    }
    
    private func data(publicKey: SecKey) -> String? {
        var error:Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(publicKey, &error) {
            let data:Data = cfdata as Data
            let b64Key = data.base64EncodedString()
            return b64Key
        }
        return nil
    }
    
    private func save(data: Data) {
        if let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            
            let now = Date()
            let formatter = DateFormatter()
            formatter.timeZone = TimeZone.current
            formatter.dateFormat = "yyyy-MM-dd--HH-mm"
            let dateString = formatter.string(from: now)

            let fileURL = dir.appendingPathComponent("Certificate_" + dateString + ".der")
            
            do {
                try data.write(to: fileURL)
            } catch {
                fatalError("Error saving certificate")
            }
        }
    }
    
}
