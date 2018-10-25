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
import CommonCrypto

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    
    
    
    var window: UIWindow?
    
    internal func application(_ application: UIApplication,
                              didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]?) -> Bool
    {
        //Get Signature from moneymonster.local.DER
        let path1 = Bundle.main.path(forResource: "moneymonster.local", ofType: "DER")!
        let url1 = URL(fileURLWithPath: path1)
        let data1 = try! Data(contentsOf: url1)

        guard let intermediateCertificate = SecCertificateCreateWithData(nil, data1 as NSData) else {
            return true
        }

        // Get Modulus from momo-ca.1.DER
        let path2 = Bundle.main.path(forResource: "momo-ca.1.crt", ofType: "DER")!
        let url2 = URL(fileURLWithPath: path2)
        let data2 = try! Data(contentsOf: url2)


        let certificate2 = SecCertificateCreateWithData(nil, data2 as CFData)
        let publicKey2: SecKey = SecCertificateCopyPublicKey(certificate2!)!

        let result = SelfSignedCompare().validate(intermediateCertificate: intermediateCertificate, with: [publicKey2])
        print(result)

        return true
    }
}

//        var signature: String = ""
//        var signatureInt: Int = 0
//        var modulus: String = ""
//        var tbs: String = ""
//        var hashed_tbs: String = ""
//        var publicKey: SecKey?
//
//        // Get Signature from moneymonster.local.DER
//        let path1 = Bundle.main.path(forResource: "moneymonster.local", ofType: "DER")!
//        let url1 = URL(fileURLWithPath: path1)
//        let data1 = try! Data(contentsOf: url1)
//
//        if let certificate = SecCertificateCreateWithData(nil, data1 as NSData) {
//            publicKey = SecCertificateCopyPublicKey(certificate)
//        }
//
//
//        let x5091 = try! X509Certificate(data: data1)
////        let publicKey = x5091.publicKey!
//        let signatureData = x5091.signature
//        let validateDate = x5091.checkValidity(<#T##date: Date##Date#>)
////        signature = "0x" + signatureData!.hexEncodedString()
////        signatureInt = Int(signature)!
//
//
//
//
//        // TODO: Extract TBS from moneymonster.local.DER
//        let allHexData = data1.hexEncodedString()
//        var sequences: [Int] = []
//        for index in 0..<allHexData.count {
//            let array = Array(allHexData)
//            let char = array[index]
//            if (index+1<allHexData.count) {
//                let nextchar = array[index + 1]
//                if (char == "3" && nextchar == "0") {
//                    sequences.append(index)
//                }
//            }
//        }
//        let beginning = sequences[1]
//        let end = sequences[sequences.count-2]
//        tbs = String(allHexData[beginning..<end])
//        
//        hashed_tbs = tbs.sha256().data(using: .utf8)!.hexEncodedString()
//
////        let hashed_tbs_data = Data(string: hashed_tbs).hexEncodedString()
//
//
//        // Get Modulus from momo-ca.1.DER
//        let path2 = Bundle.main.path(forResource: "momo-ca.1.crt", ofType: "DER")!
//        let url2 = URL(fileURLWithPath: path2)
//        let data2 = try! Data(contentsOf: url2)
//        let certificate2 = SecCertificateCreateWithData(nil, data2 as CFData)
//        let publicKey2: SecKey = SecCertificateCopyPublicKey(certificate2!)!
//        let parse = parsePublicSecKey(publicKey: publicKey2)!
//        let cert2Data = try! X509Certificate(data: data2)
//        let signature2Data = cert2Data.signature
//        modulus = parse.mod.hexEncodedString()
//        
//        
//        print("Signature: " + signature)
//        print("Modulus: " + modulus)
//        print("TBS: " + tbs)
//        print("Hashed TBS: " + hashed_tbs)
//        
//        // TODO: Calculate: pow(signature, 65537, modulus)
////        let result = Int(pow(Double(signatureInt), 65537)) % Int(modulus)!
//        let blockSize = SecKeyGetBlockSize(publicKey2)
//        var messageDecrypted = [UInt8](repeating: 0, count: blockSize)
//        var messageDecryptedSize = blockSize
////        var cipherText = signature.toPointer()
//
//        var rawBytes = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
//        let dataPointer = data2.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) in
//            CC_MD5(bytes, CC_LONG(data2.count), &rawBytes)
//        }
//
//        let status2 = SecKeyDecrypt(publicKey2, .PKCS1SHA256, dataPointer!, data2.count, &messageDecrypted, &messageDecryptedSize)
//
////
////        var error: Unmanaged<CFError>?
////        let newData = NSData(base64Encoded: signature, options: NSData.Base64DecodingOptions(rawValue: 0))!
////
////        let status = SecKeyCreateDecryptedData(publicKey2, .rsaEncryptionOAEPSHA256, newData as CFData, &error) as Data?
//
//
//
////        let status = SecKeyDecrypt(publicKey2, SecPadding.PKCS1SHA256, cipherText!, blockSize, &messageDecrypted, &messageDecryptedSize)
//
//
////        print("DIME! status: \(status)")
//        print("DIME! status PT2: \(status2)")
//
////        verify(signatureData!, signature: signatureData!, publicKey: publicKey2)
//        var decryptedData = self.decryptThatShit(publicKey2, padding: .PKCS1, cipherData: signatureData!)
//        //hashed_tbs=hashlib.sha256(tbs).hexdigest()
//        let __hashed_tbs = tbs
//
//        let hashTBS = Data.init(bytes: Array<UInt8>(hex: tbs)).sha256().hexadecimalString()
//
//        print("decryptedData: \(decryptedData?.toHexString())")
//        print("__hashed_tbs: \(__hashed_tbs)")
//
//
//        if ( decryptedData?.toHexString().suffix(64))! == hashTBS {
//            print("ALL GOOD!")
//        }
//
//
//        return true
//
//    }
//
//    func verify(_ fileData: Data, signature: Data, publicKey: SecKey) -> Bool {
//        var success = false
//        //hash the message first
//        let digestLength = Int(CC_SHA512_DIGEST_LENGTH)
//        let hashBytes = UnsafeMutablePointer<UInt8>.allocate(capacity:digestLength)
//        CC_SHA512([UInt8](fileData), CC_LONG(fileData.count), hashBytes)
//
//        //verify
//        let status = signature.withUnsafeBytes { signatureBytes in
//            return SecKeyRawVerify(publicKey, .PKCS1SHA512, hashBytes, digestLength, signatureBytes, signature.count)
//        }
//
//        if status == noErr {
//            success = true
//        } else {
//            print("Signature verify error") //-9809 : errSSLCrypto, etc
//        }
//        return success
//
//    }
//
//    func decryptThatShit(_ key: SecKey, padding: SecPadding, cipherData: Data) -> Data? {
//        guard cipherData.count == SecKeyGetBlockSize(key) else {
//            print("OH CRAP!")
//            return nil
//        }
//
//        print("da KEY: \(key)")
//
//        //output
//        let blockSize = SecKeyGetBlockSize(key)
//        var plainText = [UInt8](repeating: 0, count: blockSize)
//        var plainTextBlockSize = blockSize
//
//        let status = SecKeyDecrypt(key, [], cipherData.arrayOfBytes(), cipherData.count, &plainText, &plainTextBlockSize)
//
//        if status == noErr {
//            return Data(bytes: UnsafePointer<UInt8>(plainText), count: plainTextBlockSize)
//        } else {
//            print("Signature decryption error") //-9809 : errSSLCrypto, etc
//        }
//
//        return nil



//
//    func parsePublicSecKey(publicKey: SecKey) -> (mod: Data, exp: Data)? {
//        let pubAttributes = SecKeyCopyAttributes(publicKey) as! [String: Any]
//
//        let keySize = pubAttributes[kSecAttrKeySizeInBits as String] as! Int
//
//        let pubData  = pubAttributes[kSecValueData as String] as! Data
//        var modulus  = pubData.subdata(in: 8..<(pubData.count - 5))
//        let exponent = pubData.subdata(in: (pubData.count - 3)..<pubData.count)
//
//        if modulus.count > keySize / 8 { // --> 257 bytes
//            modulus.removeFirst(1)
//        }
//
//        return (mod: modulus, exp: exponent)
//    }
//
//
//    func sha256(string: String) -> Data? {
//        guard let messageData = string.data(using:String.Encoding.utf8) else { return nil }
//        var digestData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
//
//        _ = digestData.withUnsafeMutableBytes {digestBytes in
//            messageData.withUnsafeBytes {messageBytes in
//                CC_SHA256(messageBytes, CC_LONG(messageData.count), digestBytes)
//            }
//        }
//        return digestData
//    }
//
//}
//
//
//extension Data {
//    struct HexEncodingOptions: OptionSet {
//        let rawValue: Int
//        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
//    }
//
//    func hexEncodedString(options: HexEncodingOptions = []) -> String {
//        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
//        return map { String(format: format, $0) }.joined()
//    }
//}
//
//
//extension String: Error {}
//
//
//extension String {
//    subscript (i: Int) -> Character {
//        return self[index(startIndex, offsetBy: i)]
//    }
//    subscript (bounds: CountableRange<Int>) -> Substring {
//        let start = index(startIndex, offsetBy: bounds.lowerBound)
//        let end = index(startIndex, offsetBy: bounds.upperBound)
//        return self[start ..< end]
//    }
//    subscript (bounds: CountableClosedRange<Int>) -> Substring {
//        let start = index(startIndex, offsetBy: bounds.lowerBound)
//        let end = index(startIndex, offsetBy: bounds.upperBound)
//        return self[start ... end]
//    }
//    subscript (bounds: CountablePartialRangeFrom<Int>) -> Substring {
//        let start = index(startIndex, offsetBy: bounds.lowerBound)
//        let end = index(endIndex, offsetBy: -1)
//        return self[start ... end]
//    }
//    subscript (bounds: PartialRangeThrough<Int>) -> Substring {
//        let end = index(startIndex, offsetBy: bounds.upperBound)
//        return self[startIndex ... end]
//    }
//    subscript (bounds: PartialRangeUpTo<Int>) -> Substring {
//        let end = index(startIndex, offsetBy: bounds.upperBound)
//        return self[startIndex ..< end]
//    }
//}
//extension Substring {
//    subscript (i: Int) -> Character {
//        return self[index(startIndex, offsetBy: i)]
//    }
//    subscript (bounds: CountableRange<Int>) -> Substring {
//        let start = index(startIndex, offsetBy: bounds.lowerBound)
//        let end = index(startIndex, offsetBy: bounds.upperBound)
//        return self[start ..< end]
//    }
//    subscript (bounds: CountableClosedRange<Int>) -> Substring {
//        let start = index(startIndex, offsetBy: bounds.lowerBound)
//        let end = index(startIndex, offsetBy: bounds.upperBound)
//        return self[start ... end]
//    }
//    subscript (bounds: CountablePartialRangeFrom<Int>) -> Substring {
//        let start = index(startIndex, offsetBy: bounds.lowerBound)
//        let end = index(endIndex, offsetBy: -1)
//        return self[start ... end]
//    }
//    subscript (bounds: PartialRangeThrough<Int>) -> Substring {
//        let end = index(startIndex, offsetBy: bounds.upperBound)
//        return self[startIndex ... end]
//    }
//    subscript (bounds: PartialRangeUpTo<Int>) -> Substring {
//        let end = index(startIndex, offsetBy: bounds.upperBound)
//        return self[startIndex ..< end]
//    }
//}
////
////extension Data {
////    struct HexEncodingOptions: OptionSet {
////        let rawValue: Int
////        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
////    }
////
////    func hexEncodedString(options: HexEncodingOptions = []) -> String {
////        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
////        return map { String(format: format, $0) }.joined()
////    }
////}
//
//extension String {
//
//    func toPointer() -> UnsafePointer<UInt8>? {
//        guard let data = self.data(using: String.Encoding.utf8) else { return nil }
//
//        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
//        let stream = OutputStream(toBuffer: buffer, capacity: data.count)
//
//        stream.open()
//        data.withUnsafeBytes({ (p: UnsafePointer<UInt8>) -> Void in
//            stream.write(p, maxLength: data.count)
//        })
//
//        stream.close()
//
//        return UnsafePointer<UInt8>(buffer)
//    }
//}
//
////extension Data {
////    public func hexadecimalString() -> String {
////        let string = NSMutableString(capacity: count * 2)
////        var byte: UInt8 = 0
////        for i in 0 ..< count {
////            copyBytes(to: &byte, from: i..<index(after: i))
////            string.appendFormat("%02x", byte)
////        }
////
////        return string as String
////    }
////    public var hexString : String {
////        return self.hexadecimalString()
////    }
////    public var base64String:String {
////        return self.base64EncodedString(options: NSData.Base64EncodingOptions())
////    }
////    /// Array of UInt8
////    public func arrayOfBytes() -> [UInt8] {
////        let count = self.count / MemoryLayout<UInt8>.size
////        var bytesArray = [UInt8](repeating: 0, count: count)
////        (self as NSData).getBytes(&bytesArray, length:count * MemoryLayout<UInt8>.size)
////        return bytesArray
////    }
////}



