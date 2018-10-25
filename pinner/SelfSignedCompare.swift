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
    let tbs: String
    let validDate: Bool
    var hashedTBS: String {
        get {
            return Data(bytes: Array<UInt8>(hex: tbs)).sha256().hexString
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
//                let tbsData = Data(bytes: Array<UInt8>(hex: tbs)).sha256() //SelfSignedCompare.sha256(string: tbs)!//
                let validDate = x509Data.checkValidity(Date())

                return STCertificateComponents(signature: signatureData, tbs: tbs, validDate: validDate)
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
    
    func sha256() -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(self.count), &hash)
        }
        return Data(bytes: hash)
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

extension Array {
    init(reserveCapacity: Int) {
        self = Array<Element>()
        self.reserveCapacity(reserveCapacity)
    }
    
    var slice: ArraySlice<Element> {
        return self[self.startIndex..<self.endIndex]
    }
}

extension Array {
    
    /// split in chunks with given chunk size
    public func chunks(size chunksize: Int) -> Array<Array<Element>> {
        var words = Array<Array<Element>>()
        words.reserveCapacity(count / chunksize)
        for idx in stride(from: chunksize, through: count, by: chunksize) {
            words.append(Array(self[idx - chunksize..<idx])) // slow for large table
        }
        let remainder = suffix(count % chunksize)
        if !remainder.isEmpty {
            words.append(Array(remainder))
        }
        return words
    }
}

extension Array where Element == UInt8 {
    
    public init(hex: String) {
        self.init(reserveCapacity: hex.unicodeScalars.lazy.underestimatedCount)
        var buffer: UInt8?
        var skip = hex.hasPrefix("0x") ? 2 : 0
        for char in hex.unicodeScalars.lazy {
            guard skip == 0 else {
                skip -= 1
                continue
            }
            guard char.value >= 48 && char.value <= 102 else {
                removeAll()
                return
            }
            let v: UInt8
            let c: UInt8 = UInt8(char.value)
            switch c {
            case let c where c <= 57:
                v = c - 48
            case let c where c >= 65 && c <= 70:
                v = c - 55
            case let c where c >= 97:
                v = c - 87
            default:
                removeAll()
                return
            }
            if let b = buffer {
                append(b << 4 | v)
                buffer = nil
            } else {
                buffer = v
            }
        }
        if let b = buffer {
            append(b)
        }
    }
}
