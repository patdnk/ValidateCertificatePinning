//
//  SelfSignedCompare.swift
//  pinner
//
//  Created by Martinez, Ricardo (ISBANUK) on 25/10/2018.
//  Copyright © 2018 Infinum. All rights reserved.
//

import Foundation
import ASN1Decoder
import CommonCrypto

public struct STCertificateComponents {
    let signature: Data
    let tbs: Data
    let tbsString: String
    let validDate: Bool
    var hashedTBS: String {
        get {
            return SelfSignedCompare.sha256(string: tbsString)!.hexEncodedString()
        }
    }
}


public class SelfSignedCompare {

    let kHashOffset = 64

    //decrypt the signature with pinned keys
    public final func validate(intermediateCertificate: SecCertificate, with keys: [SecKey]) -> Bool {

        //call the extraction on external Certificate
        if let certificateComponents = self.extractCertificateComponents(certificate: intermediateCertificate) {
            for key in keys {
                //try decryption and comparison
                if let decryptedSignature = self.decryptSignature(key, cipherData: certificateComponents.signature) {
                    if self.compare(decryptedSignature: decryptedSignature, hashedTBS: certificateComponents.hashedTBS, validDate: certificateComponents.validDate) {
                        return true
                    }
                }

            }
        }

        return false

    }

    //extract the components from SelfSigned IOT device
    //tbs
    //signature

    fileprivate func extractCertificateComponents(certificate: SecCertificate) -> STCertificateComponents? {
        let certificateData = SecCertificateCopyData(certificate)

        do {
            let x509Data = try X509Certificate(data: certificateData as Data)
            if let signatureData = x509Data.signature {
                let allHexData = (certificateData as Data).hexEncodedString()

                var sequences: [Int] = []
                for index in 0..<allHexData.count {
                    let array = Array(allHexData)
                    let char = array[index]
                    if (index+1<allHexData.count) {
                        let nextchar = array[index + 1]
                        if (char == "3" && nextchar == "0") {
                            sequences.append(index)
                        }
                    }
                }
                let beginning = sequences[1]
                let end = sequences[sequences.count-2]
                let tbs = String(allHexData[beginning..<end])
                let tbsData = SelfSignedCompare.sha256(string: tbs)!//Data(bytes: Array<UInt8>(hex: tbs)).sha256()
                let validDate = x509Data.checkValidity(Date())

                return STCertificateComponents.init(signature: signatureData, tbs: tbsData, tbsString: tbs, validDate: validDate)
            }

        } catch {
            return nil
        }
        return nil
    }


    //compare decrypted signature with hashedTBS
    fileprivate func compare(decryptedSignature: Data, hashedTBS: String, validDate: Bool) -> Bool {

        if validDate {
            if (decryptedSignature.hexadecimalString().suffix(kHashOffset)) == hashedTBS {
                return true
            }
        }

        return false

    }

    fileprivate func decryptSignature(_ key: SecKey, cipherData: Data) -> Data? {
        guard cipherData.count == SecKeyGetBlockSize(key) else {
            return nil
        }

        //output
        let blockSize = SecKeyGetBlockSize(key)
        var plainText = [UInt8](repeating: 0, count: blockSize)
        var plainTextBlockSize = blockSize

        let status = SecKeyDecrypt(key, [], cipherData.arrayOfBytes(), cipherData.count, &plainText, &plainTextBlockSize)

        if status == noErr {
            return Data(bytes: UnsafePointer<UInt8>(plainText), count: plainTextBlockSize)
        } else {
            print("Signature decryption error \(status)") //-9809 : errSSLCrypto, etc
        }

        return nil

    }

    //TODO: externalize -> extension library
    fileprivate static func sha256(string: String) -> Data? {
        guard let messageData = string.data(using:String.Encoding.utf8) else { return nil }
        var digestData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))

        _ = digestData.withUnsafeMutableBytes {digestBytes in
            messageData.withUnsafeBytes {messageBytes in
                CC_SHA256(messageBytes, CC_LONG(messageData.count), digestBytes)
            }
        }
        return digestData
    }

}



extension Data {

    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    public func hexadecimalString() -> String {
        let string = NSMutableString(capacity: count * 2)
        var byte: UInt8 = 0
        for i in 0 ..< count {
            copyBytes(to: &byte, from: i..<index(after: i))
            string.appendFormat("%02x", byte)
        }

        return string as String
    }
    public var hexString : String {
        return self.hexadecimalString()
    }
    public var base64String:String {
        return self.base64EncodedString(options: NSData.Base64EncodingOptions())
    }
    /// Array of UInt8
    public func arrayOfBytes() -> [UInt8] {
        let count = self.count / MemoryLayout<UInt8>.size
        var bytesArray = [UInt8](repeating: 0, count: count)
        (self as NSData).getBytes(&bytesArray, length:count * MemoryLayout<UInt8>.size)
        return bytesArray
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }

}

extension String: Error {}


extension String {
    subscript (i: Int) -> Character {
        return self[index(startIndex, offsetBy: i)]
    }
    subscript (bounds: CountableRange<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[start ..< end]
    }
    subscript (bounds: CountableClosedRange<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[start ... end]
    }
    subscript (bounds: CountablePartialRangeFrom<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(endIndex, offsetBy: -1)
        return self[start ... end]
    }
    subscript (bounds: PartialRangeThrough<Int>) -> Substring {
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[startIndex ... end]
    }
    subscript (bounds: PartialRangeUpTo<Int>) -> Substring {
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[startIndex ..< end]
    }
}
extension Substring {
    subscript (i: Int) -> Character {
        return self[index(startIndex, offsetBy: i)]
    }
    subscript (bounds: CountableRange<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[start ..< end]
    }
    subscript (bounds: CountableClosedRange<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[start ... end]
    }
    subscript (bounds: CountablePartialRangeFrom<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(endIndex, offsetBy: -1)
        return self[start ... end]
    }
    subscript (bounds: PartialRangeThrough<Int>) -> Substring {
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[startIndex ... end]
    }
    subscript (bounds: PartialRangeUpTo<Int>) -> Substring {
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[startIndex ..< end]
    }
}

