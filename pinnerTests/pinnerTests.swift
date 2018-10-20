//
//  pinnerTests.swift
//  pinnerTests
//
//  Created by Ricardo Maqueda Martinez on 20/10/2018.
//  Copyright © 2018 Infinum. All rights reserved.
//

import XCTest
import ASN1Decoder

class pinnerTests: XCTestCase {
    
    func testExample() {
        
        if let path = Bundle.main.path(forResource: "moneymonster.local", ofType: "DER") {
            let url = URL(fileURLWithPath: path)
            let data = try! Data(contentsOf: url)
            
            do {
                let x509 = try X509Certificate(data: data)
                
                let subject = x509.subjectDistinguishedName ?? ""
                
            } catch {
                print(error)
            }
        }
        
    }
    
}
