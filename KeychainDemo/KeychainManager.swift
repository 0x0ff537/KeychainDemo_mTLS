import Foundation
import Security

class KeychainManager: NSObject {
    
    static let shared = KeychainManager()
    
    // Configuration
    private let certificateLabel = "com.keychaindemo.certificate"
    private let privateKeyLabel = "com.keychaindemo.privatekey"
    private let p12Password = "training"  // Must match server
    
    // For mTLS
    private var clientIdentity: SecIdentity?
    
    private override init() {
        super.init()
    }
    
    // MARK: - Download and Import Certificate from Server
    
    func downloadAndImportCertificate(from serverURL: String, completion: @escaping (Result<String, Error>) -> Void) {
        // Build URL for certificate download (same server, /download endpoint)
        guard let baseURL = URL(string: serverURL),
              let host = baseURL.host,
              let port = baseURL.port else {
            completion(.failure(NSError(domain: "KeychainManager", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid server URL"])))
            return
        }
        
        let downloadURLString = "https://\(host):\(port)/download/client.p12"
        guard let downloadURL = URL(string: downloadURLString) else {
            completion(.failure(NSError(domain: "KeychainManager", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid download URL"])))
            return
        }
        
        print("[KeychainManager] Downloading certificate from: \(downloadURL.absoluteString)")
        
        // Create session that accepts self-signed server certs
        let config = URLSessionConfiguration.default
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        
        let task = session.dataTask(with: downloadURL) { [weak self] data, response, error in
            guard let self = self else { return }
            
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(NSError(domain: "KeychainManager", code: -2, userInfo: [NSLocalizedDescriptionKey: "Invalid response"])))
                return
            }
            
            guard httpResponse.statusCode == 200 else {
                completion(.failure(NSError(domain: "KeychainManager", code: -3, userInfo: [NSLocalizedDescriptionKey: "Server returned status \(httpResponse.statusCode)"])))
                return
            }
            
            guard let p12Data = data, !p12Data.isEmpty else {
                completion(.failure(NSError(domain: "KeychainManager", code: -4, userInfo: [NSLocalizedDescriptionKey: "Empty response from server"])))
                return
            }
            
            print("[KeychainManager] Downloaded \(p12Data.count) bytes")
            
            // Import the P12 data
            let importResult = self.importP12(data: p12Data, password: self.p12Password)
            completion(importResult)
        }
        
        task.resume()
    }
    
    // MARK: - Import P12 Data
    
    private func importP12(data: Data, password: String) -> Result<String, Error> {
        // Delete any existing items first
        _ = deleteAllItems()
        
        // Import options
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: password
        ]
        
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        
        guard status == errSecSuccess else {
            let message: String
            switch status {
            case errSecAuthFailed:
                message = "Wrong password for P12 file"
            case errSecDecode:
                message = "Invalid P12 file format"
            default:
                message = "Failed to import P12: OSStatus \(status)"
            }
            return .failure(NSError(domain: "KeychainManager", code: Int(status), userInfo: [NSLocalizedDescriptionKey: message]))
        }
        
        guard let itemsArray = items as? [[String: Any]], let firstItem = itemsArray.first else {
            return .failure(NSError(domain: "KeychainManager", code: -5, userInfo: [NSLocalizedDescriptionKey: "No items in P12 file"]))
        }
        
        // Extract identity
        guard let identity = firstItem[kSecImportItemIdentity as String] else {
            return .failure(NSError(domain: "KeychainManager", code: -6, userInfo: [NSLocalizedDescriptionKey: "No identity in P12 file"]))
        }
        
        let secIdentity = identity as! SecIdentity
        
        // Extract certificate from identity
        var certificate: SecCertificate?
        let certStatus = SecIdentityCopyCertificate(secIdentity, &certificate)
        guard certStatus == errSecSuccess, let cert = certificate else {
            return .failure(NSError(domain: "KeychainManager", code: -7, userInfo: [NSLocalizedDescriptionKey: "Failed to extract certificate from identity"]))
        }
        
        // Extract private key from identity
        var privateKey: SecKey?
        let keyStatus = SecIdentityCopyPrivateKey(secIdentity, &privateKey)
        guard keyStatus == errSecSuccess, let key = privateKey else {
            return .failure(NSError(domain: "KeychainManager", code: -8, userInfo: [NSLocalizedDescriptionKey: "Failed to extract private key from identity"]))
        }
        
        // Store certificate in Keychain
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certificateLabel,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
            kSecValueRef as String: cert
        ]
        
        var addStatus = SecItemAdd(certQuery as CFDictionary, nil)
        if addStatus != errSecSuccess && addStatus != errSecDuplicateItem {
            print("[KeychainManager] Warning: Failed to store certificate: \(addStatus)")
        }
        
        // Store private key in Keychain
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: privateKeyLabel,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
            kSecValueRef as String: key
        ]
        
        addStatus = SecItemAdd(keyQuery as CFDictionary, nil)
        if addStatus != errSecSuccess && addStatus != errSecDuplicateItem {
            print("[KeychainManager] Warning: Failed to store private key: \(addStatus)")
        }
        
        // Store the identity for mTLS use
        self.clientIdentity = secIdentity
        
        print("[KeychainManager] Certificate imported successfully!")
        return .success("Certificate imported successfully from server!")
    }
    
    // MARK: - Retrieve Certificate
    
    func retrieveCertificate() -> Result<(SecCertificate, Data), Error> {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certificateLabel,
            kSecReturnRef as String: true,
            kSecReturnData as String: true
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess, let dict = result as? [String: Any],
           let certRef = dict[kSecValueRef as String],
           let certData = dict[kSecValueData as String] as? Data {
            return .success((certRef as! SecCertificate, certData))
        } else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Certificate not found: \(status)"]))
        }
    }
    
    // MARK: - Retrieve Private Key
    
    func retrievePrivateKey() -> Result<(SecKey, Data?), Error> {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: privateKeyLabel,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess, let keyRef = result {
            let privateKey = keyRef as! SecKey
            
            // Try to export key data
            var error: Unmanaged<CFError>?
            let keyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data?
            
            return .success((privateKey, keyData))
        } else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Private key not found: \(status)"]))
        }
    }
    
    // MARK: - Retrieve Identity
    
    func retrieveIdentity() -> Result<SecIdentity, Error> {
        // Try cached identity first
        if let identity = clientIdentity {
            return .success(identity)
        }
        
        // Otherwise, reconstruct from keychain
        guard case .success(let (certificate, _)) = retrieveCertificate() else {
            return .failure(NSError(domain: "KeychainManager", code: -10, userInfo: [NSLocalizedDescriptionKey: "Certificate not found"]))
        }
        
        guard case .success(let (privateKey, _)) = retrievePrivateKey() else {
            return .failure(NSError(domain: "KeychainManager", code: -11, userInfo: [NSLocalizedDescriptionKey: "Private key not found"]))
        }
        
        guard let identity = SecIdentityCreate(kCFAllocatorDefault, certificate, privateKey) else {
            return .failure(NSError(domain: "KeychainManager", code: -12, userInfo: [NSLocalizedDescriptionKey: "Failed to create identity"]))
        }
        
        self.clientIdentity = identity
        return .success(identity)
    }
    
    // MARK: - Check if Identity Exists
    
    func identityExists() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certificateLabel,
            kSecReturnRef as String: false
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    // MARK: - Delete All Stored Items
    
    func deleteAllItems() -> Result<Void, Error> {
        self.clientIdentity = nil
        
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: privateKeyLabel
        ]
        SecItemDelete(keyQuery as CFDictionary)
        
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certificateLabel
        ]
        SecItemDelete(certQuery as CFDictionary)
        
        return .success(())
    }
    
    // MARK: - Get Certificate Info
    
    func getCertificateInfo() -> String? {
        switch retrieveCertificate() {
        case .success(let (cert, data)):
            var info = ""
            
            if let summary = SecCertificateCopySubjectSummary(cert) as String? {
                info += "Subject: \(summary)\n"
            }
            
            var error: Unmanaged<CFError>?
            if let serialData = SecCertificateCopySerialNumberData(cert, &error) as Data? {
                let serialHex = serialData.map { String(format: "%02X", $0) }.joined(separator: ":")
                info += "Serial: \(serialHex)\n"
            }
            
            info += "Size: \(data.count) bytes\n"
            info += "DER (first 32 bytes):\n\(data.prefix(32).map { String(format: "%02X", $0) }.joined(separator: " "))"
            
            return info
            
        case .failure:
            return nil
        }
    }
    
    // MARK: - Get Private Key Info
    
    func getPrivateKeyInfo() -> String? {
        switch retrievePrivateKey() {
        case .success(let (key, data)):
            var info = ""
            
            if let attributes = SecKeyCopyAttributes(key) as? [String: Any] {
                if let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int {
                    info += "Key Size: \(keySize) bits\n"
                }
            }
            
            if let keyData = data {
                info += "Extractable: YES ⚠️\n"
                info += "Size: \(keyData.count) bytes\n"
                info += "Data (first 32 bytes):\n\(keyData.prefix(32).map { String(format: "%02X", $0) }.joined(separator: " "))"
            } else {
                info += "Extractable: NO (Secure Enclave)"
            }
            
            return info
            
        case .failure:
            return nil
        }
    }
    
    // MARK: - mTLS Network Requests
    
    func sendGETRequest(to serverURL: String, completion: @escaping (Result<(Int, String), Error>) -> Void) {
        sendRequest(to: serverURL, method: "GET", body: nil, completion: completion)
    }
    
    func sendPOSTRequest(to serverURL: String, body: [String: Any], completion: @escaping (Result<(Int, String), Error>) -> Void) {
        sendRequest(to: serverURL, method: "POST", body: body, completion: completion)
    }
    
    private func sendRequest(to serverURL: String, method: String, body: [String: Any]?, completion: @escaping (Result<(Int, String), Error>) -> Void) {
        
        guard let url = URL(string: serverURL) else {
            completion(.failure(NSError(domain: "KeychainManager", code: -100, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        
        // Load identity from keychain
        switch retrieveIdentity() {
        case .success(let identity):
            self.clientIdentity = identity
        case .failure(let error):
            completion(.failure(error))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("KeychainDemo/1.0", forHTTPHeaderField: "User-Agent")
        
        if let body = body {
            request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        }
        
        let config = URLSessionConfiguration.default
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        
        let task = session.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(NSError(domain: "KeychainManager", code: -101, userInfo: [NSLocalizedDescriptionKey: "Invalid response"])))
                return
            }
            
            let statusCode = httpResponse.statusCode
            let responseBody = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            
            completion(.success((statusCode, responseBody)))
        }
        
        task.resume()
    }
}

// MARK: - URLSessionDelegate for mTLS and Self-Signed Server Certs

extension KeychainManager: URLSessionDelegate {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        let protectionSpace = challenge.protectionSpace
        
        // Handle server trust (accept self-signed server certificates)
        if protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let serverTrust = protectionSpace.serverTrust {
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
                return
            }
        }
        
        // Handle client certificate request
        if protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            print("[mTLS] Server requested client certificate")
            
            if let identity = self.clientIdentity {
                // Get certificate from identity
                var certificateRef: SecCertificate?
                SecIdentityCopyCertificate(identity, &certificateRef)
                
                var certificates: [SecCertificate] = []
                if let cert = certificateRef {
                    certificates.append(cert)
                    if let summary = SecCertificateCopySubjectSummary(cert) as String? {
                        print("[mTLS] Presenting certificate: \(summary)")
                    }
                }
                
                let credential = URLCredential(identity: identity, certificates: certificates as [Any], persistence: .forSession)
                completionHandler(.useCredential, credential)
                return
            } else {
                print("[mTLS] No client identity available!")
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }
        
        completionHandler(.performDefaultHandling, nil)
    }
}
