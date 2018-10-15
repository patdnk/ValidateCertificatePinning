//
//  GPCertUtils.swift
//  GlobalPay
//
//  Created by Sanz Herrero, Alex (Isban) on 14/09/2017.
//  Copyright © 2017 Santander Plc. All rights reserved.
//

import Foundation

    public class GPCertUtils{
        class func dump() {
            GPCertUtils.dumpPublicKeys()
        }
    }
    
    internal extension GPCertUtils {
        internal static func dumpPublicKeys(publicKeys: [(SecKey, String)] = GPCertUtils.publicKeys()) {
            var error:Unmanaged<CFError>?
            print ("\n >>>>>>>> DUMPING PUBLIC KEYS FROM CERTIFICATES IN BUNNDLE <<<<<<<<<<")
            
            for publicKey in publicKeys {
                print ("\n\nCN = \(publicKey.1)")
                if let cfdata = SecKeyCopyExternalRepresentation(publicKey.0, &error) {
                    let data:Data = cfdata as Data
                    let b64Key = data.base64EncodedString(options: Data.Base64EncodingOptions.init(rawValue: 0))
                    print ("\n     :: Public Key [Base64] :: ")
                    print(b64Key)
                    let array = data.withUnsafeBytes {
                        [UInt8](UnsafeBufferPointer(start: $0, count: data.count))
                    }
                    print ("\n     :: Public Key [Array<UInt8>] :: ")
                    print(array)
                }
            }
            print ("\n >>>>>>>> END DUMPING PUBLIC KEYS FROM CERTIFICATES IN BUNNDLE <<<<<<<<<<\n\n")
        }
        
        private static func publicKeys(in bundle: Bundle = Bundle.main) -> [(SecKey, String)] {
            var publicKeys: [(SecKey, String)] = []
            
            for certificate in certificates(in: bundle) {
                let (publicKey, name) = self.publicKey(for: certificate)
                if let pubKey = publicKey {
                    publicKeys.append((pubKey, name! as String))
                }
            }
            return publicKeys
        }
        
        private static func certificates(in bundle: Bundle = Bundle.main) -> [SecCertificate] {
            var certificates: [SecCertificate] = []
            
            let paths = Set([".cer", ".CER", ".crt", ".CRT", ".der", ".DER"].map { fileExtension in
                bundle.paths(forResourcesOfType: fileExtension, inDirectory: nil)
                }.joined())
            
            for path in paths {
                if
                    let certificateData = try? Data(contentsOf: URL(fileURLWithPath: path)) as CFData,
                    let certificate = SecCertificateCreateWithData(nil, certificateData)
                {
                    
                    certificates.append(certificate)
                }
            }
            return certificates
        }
        
        private static func publicKey(for certificate: SecCertificate) -> (SecKey?, CFString?){
            var publicKey: SecKey?
            
            let policy = SecPolicyCreateBasicX509()
            var trust: SecTrust?
            let trustCreationStatus = SecTrustCreateWithCertificates(certificate, policy, &trust)
            let summary = SecCertificateCopySubjectSummary(certificate)
            
            if let trust = trust, trustCreationStatus == errSecSuccess {
                publicKey = SecTrustCopyPublicKey(trust)
            }
            
            return (publicKey, summary)
        }
    }


