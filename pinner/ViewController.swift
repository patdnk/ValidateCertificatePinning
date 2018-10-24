//
//  ViewController.swift
//  pinner
//
//  Created by Adis on 15/09/2017.
//  Copyright © 2017 Infinum. All rights reserved.
//

import UIKit

import Alamofire

class ViewController: UIViewController, UITableViewDelegate, UITableViewDataSource {
    var sessionManager = SessionManager()
    let customSessionDelegate = CustomSessionDelegate()
    let otherDelegate = SelftSignerSessionDelegate()
    var selectedKey: SecKey?
    
    @IBOutlet weak var urlTextField: UITextField!
    @IBOutlet weak var resultLabel: UILabel!
    @IBOutlet weak var certificatesTableView: UITableView!
    
    var url: String {
        get {
            if let text = urlTextField.text {
                return text
            } else {
                return ""
            }
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        certificatesTableView.delegate = self
        certificatesTableView.dataSource = self
        certificatesTableView.refreshControl = UIRefreshControl()
        certificatesTableView.refreshControl?.addTarget(self, action: #selector(refreshTable(_:)), for: .valueChanged)
    }
    
    @objc private func refreshTable(_ sender: Any) {
        certificatesTableView.refreshControl?.endRefreshing()
        certificatesTableView.reloadData()
    }
    
    // MARK: TableViewDelegate and DataSource
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return certificatesFiles().count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let file = certificatesFiles()[indexPath.row]
        let fileUrl = NSURL(fileURLWithPath: file)
        let filename = fileUrl.lastPathComponent
        
        let cell = tableView.dequeueReusableCell(withIdentifier: "CertificatesCell", for: indexPath)
        cell.textLabel?.text = filename
        cell.detailTextLabel?.text = fileUrl.absoluteString
        
        return cell
    }
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let file = certificatesFiles()[indexPath.row]
        let url = URL(string: file)!
        
        if let selectedKey = key(url: url) {
            self.selectedKey = selectedKey
            customSessionDelegate.key = selectedKey
        } else {
            let alert = UIAlertController(title: "Alert", message: "The file doesn´t contain a valid public Key", preferredStyle: UIAlertControllerStyle.alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
            
            tableView.deselectRow(at: indexPath, animated: true)
            selectedKey = nil
        }
        
        print(url)
    }
    
    // MARK: Helpers
    func certificatesFiles() -> [String] {
        var all = certificatesFilesBundle()
        all.append(contentsOf: certificatesFilesDocuments())
        
        return all
    }
    
    func certificatesFilesBundle() -> [String] {
        let paths = Array([".cer", ".CER", ".crt", ".CRT", ".der", ".DER"].map { fileExtension in
            Bundle.main.paths(forResourcesOfType: fileExtension, inDirectory: nil)
            }.joined())

        return paths.map({
            "file://\($0)"
        })
    }
    
    func certificatesFilesDocuments() -> [String] {
        let fileManager = FileManager.default
        let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        do {
            let fileURLs = try fileManager.contentsOfDirectory(at: documentsURL, includingPropertiesForKeys: nil).map {
                $0.absoluteString
            }
            
            let namePredicate = NSPredicate(format: "self ENDSWITH '.der'");
            let filteredArray = fileURLs.filter { namePredicate.evaluate(with: $0) };
        
            return filteredArray
        } catch {
            print("Error while enumerating files \(documentsURL.path): \(error.localizedDescription)")
            fatalError("Error reading document dir")
        }
        
        return []
    }
    
    func key(forResource resource: String, withExtension aExtension: String) -> SecKey? {
        if let pinnedCertificateURL = Bundle.main.url(forResource: resource, withExtension: aExtension) {
            do {
                let pinnedCertificateData = try Data(contentsOf: pinnedCertificateURL) as CFData
                if let pinnedCertificate = SecCertificateCreateWithData(nil, pinnedCertificateData), let key = publicKey(for: pinnedCertificate) {
                    return key
                }
            } catch (_) {
                return nil
            }
        }

        return nil
    }
    
    func key(url: URL) -> SecKey? {
        do {
            let pinnedCertificateData = try Data(contentsOf: url) as CFData
            if let pinnedCertificate = SecCertificateCreateWithData(nil, pinnedCertificateData), let key = publicKey(for: pinnedCertificate) {
                return key
            }
        } catch {
            print(error)
            return nil
        }
        return nil
    }

    
    // MARK: - Actions -
    
    fileprivate func showResult(success: Bool) {
        if success {
            resultLabel.textColor = UIColor(red:0.00, green:0.75, blue:0.00, alpha:1.0)
            resultLabel.text = "🚀 Success"
        } else {
            resultLabel.textColor = .black
            resultLabel.text = "🚫 Request failed"
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            self?.resultLabel.text = ""
        }
    }
    
    @IBAction func didPressDownloadButton(_ sender: Any) {
        sessionManager = SessionManager(
            delegate: DownloadSessionDelegate(),
            serverTrustPolicyManager: CustomServerTrustPolicyManager(
                policies: [:]
            )
        )
        
        sessionManager.request(url).response { response in
            self.showResult(success: response.response != nil)
            self.certificatesTableView.reloadData()
        }
    }
    
    @IBAction func testWithNoPin() {
        let url = URL(string: self.url)!
        let session = URLSession(configuration: .default, delegate: otherDelegate, delegateQueue: nil)

        let task = session.dataTask(with: url, completionHandler: { (data, response, error) in
            DispatchQueue.main.async {
                self.showResult(success: response != nil)
            }
        })
        task.resume()
    }
    
    @IBAction func testWithAlamofireDefaultPin() {
        guard selectedKey != nil else {
            showSelectedKeyMessage()
            return
        }
        
        let aurl = URL(string: self.url)
        let domain = aurl!.host!

        let serverTrustPolicies: [String: ServerTrustPolicy] = [
            domain: .pinPublicKeys(
                publicKeys: [selectedKey!],
                validateCertificateChain: false,
                validateHost: false
            )
        ]
        
        sessionManager = SessionManager(
            serverTrustPolicyManager: ServerTrustPolicyManager(
                policies: serverTrustPolicies
            )
        )
        
        sessionManager.request(url).response { response in
            self.showResult(success: response.response != nil)
            if (response.error != nil) {
                print(response.error!)
            }
        }
    }
    
    @IBAction func testWithCustomPolicyManager() {
        guard selectedKey != nil else {
            showSelectedKeyMessage()
            return
        }
        let aurl = URL(string: self.url)
        let domain = aurl!.host!
        
        let serverTrustPolicies: [String: ServerTrustPolicy] = [
            domain: .pinPublicKeys(
                publicKeys: [selectedKey!],
                validateCertificateChain: false,
                validateHost: false
            )
        ]
        
        sessionManager = SessionManager(
            serverTrustPolicyManager: CustomServerTrustPolicyManager(
                policies: serverTrustPolicies
            )
        )
        
        sessionManager.request(url).response { response in
            self.showResult(success: response.response != nil)
            if (response.error != nil) {
                print(response.error!)
            }
        }
    }
    
    @IBAction func testWithNSURLSessionPin() {
        guard selectedKey != nil else {
            showSelectedKeyMessage()
            return
        }
        
        let url = URL(string: self.url)! // Pardon my assumption
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        
        let task = session.dataTask(with: url, completionHandler: { (data, response, error) in
            DispatchQueue.main.async {
                self.showResult(success: response != nil)
                if (error != nil) {
                    print(error!)
                }
            }
        })
        task.resume()
    }
    
    @IBAction func testWithCustomSessionDelegate() {
        guard selectedKey != nil else {
            showSelectedKeyMessage()
            return
        }
        
        sessionManager = SessionManager(
            delegate: customSessionDelegate, // Feeding our own session delegate
            serverTrustPolicyManager: CustomServerTrustPolicyManager(
                policies: [:]
            )
        )
        
        sessionManager.request(url).response { response in
            self.showResult(success: response.response != nil)
            if (response.error != nil) {
                print(response.error!)
            }
        }
    }
    
    func showSelectedKeyMessage() {
        let alert = UIAlertController(title: "Alert", message: "Select a file first", preferredStyle: UIAlertControllerStyle.alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

}

extension ViewController: URLSessionDelegate {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0 else {
            // This case will probably get handled by ATS, but still...
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Compare the server certificate with our own stored
//        if let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0) {
//            let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
//
//            if pinnedCertificates().contains(serverCertificateData) {
//                completionHandler(.useCredential, URLCredential(trust: trust))
//                return
//            }
//        }
        
        // Or, compare the public keys
        if let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0), let serverCertificateKey = publicKey(for: serverCertificate) {
            if pinnedKeys().contains(serverCertificateKey) {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
        }
        
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
    
//    fileprivate func pinnedCertificates() -> [Data] {
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
    
    fileprivate func pinnedKeys() -> [SecKey] {
        var publicKeys: [SecKey] = []
        
        if let selectedKey = self.selectedKey {
            publicKeys.append(selectedKey)
        }
        
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
        
        return publicKeys
    }
    
    // Implementation from Alamofire
    fileprivate func publicKey(for certificate: SecCertificate) -> SecKey? {
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

