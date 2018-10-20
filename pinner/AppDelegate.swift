//
//  AppDelegate.swift
//  pinner
//
//  Created by Adis on 15/09/2017.
//  Copyright © 2017 Infinum. All rights reserved.
//

import UIKit
import ASN1Decoder
import Security

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    
    
    
    var window: UIWindow?
    
    internal func application(_ application: UIApplication,
                              didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool
    {
        
        
        var signature: String = ""
        var modulus: String = ""
        var tbs: String = ""
        
        // Get Signature from moneymonster.local.DER
        let path1 = Bundle.main.path(forResource: "moneymonster.local", ofType: "DER")!
        let url1 = URL(fileURLWithPath: path1)
        let data1 = try! Data(contentsOf: url1)
        let x5091 = try! X509Certificate(data: data1)
        let signatureData = x5091.signature
        signature = signatureData!.hexEncodedString()
        
        // TODO: Extract TBS from moneymonster.local.DER
        
        // Get Modulus from momo-ca.1.DER
        let path2 = Bundle.main.path(forResource: "momo-ca.1.crt", ofType: "DER")!
        let url2 = URL(fileURLWithPath: path2)
        let data2 = try! Data(contentsOf: url2)
        let certificate2 = SecCertificateCreateWithData(nil, data2 as CFData)
        let publicKey2: SecKey = SecCertificateCopyPublicKey(certificate2!)!
        let parse = parsePublicSecKey(publicKey: publicKey2)!
        modulus = parse.mod.hexEncodedString()
        
        
        print("Signature: " + signature)
        print("Modulus: " + modulus)
        print("TBS: " + tbs)
        
        // TODO: Calculate: pow(signature, 65537, modulus)
        // let result = pow(signature, 65537)
        
        return true
    }
    
    
    func parsePublicSecKey(publicKey: SecKey) -> (mod: Data, exp: Data)? {
        let pubAttributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
  
        let keySize = pubAttributes[kSecAttrKeySizeInBits as String] as! Int
        
        let pubData  = pubAttributes[kSecValueData as String] as! Data
        var modulus  = pubData.subdata(in: 8..<(pubData.count - 5))
        let exponent = pubData.subdata(in: (pubData.count - 3)..<pubData.count)
        
        if modulus.count > keySize / 8 { // --> 257 bytes
            modulus.removeFirst(1)
        }
        
        return (mod: modulus, exp: exponent)
    }

}


extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }
    
    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}


extension String: Error {}
