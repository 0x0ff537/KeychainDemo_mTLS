import UIKit

class MainViewController: UIViewController {
    
    // MARK: - UI Elements
    
    private let scrollView = UIScrollView()
    private let contentView = UIView()
    
    private let titleLabel: UILabel = {
        let label = UILabel()
        label.text = "🔐 Keychain Security Demo"
        label.font = UIFont.systemFont(ofSize: 24, weight: .bold)
        label.textAlignment = .center
        return label
    }()
    
    private let descriptionLabel: UILabel = {
        let label = UILabel()
        label.text = "Practice extracting client certificates and private keys from the iOS Keychain using Frida. Includes mTLS server communication."
        label.font = UIFont.systemFont(ofSize: 14)
        label.textColor = .darkGray
        label.textAlignment = .center
        label.numberOfLines = 0
        return label
    }()
    
    private let statusLabel: UILabel = {
        let label = UILabel()
        label.text = "Status: No certificate"
        label.font = UIFont.systemFont(ofSize: 14, weight: .medium)
        label.textColor = .systemOrange
        label.textAlignment = .center
        label.numberOfLines = 0
        return label
    }()
    
    // Server URL Section
    private let serverSectionLabel: UILabel = {
        let label = UILabel()
        label.text = "🌐 Server Configuration"
        label.font = UIFont.systemFont(ofSize: 18, weight: .bold)
        label.textAlignment = .center
        return label
    }()
    
    private let serverURLTextField: UITextField = {
        let textField = UITextField()
        textField.placeholder = "https://192.168.1.100:8443"
        textField.text = "https://192.168.1.100:8443"
        textField.borderStyle = .roundedRect
        textField.autocapitalizationType = .none
        textField.autocorrectionType = .no
        textField.keyboardType = .URL
        textField.font = UIFont.monospacedSystemFont(ofSize: 14, weight: .regular)
        return textField
    }()
    
    private let downloadCertButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("📥 Download Certificate from Server", for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        button.backgroundColor = .systemBlue
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 10
        return button
    }()
    
    // Certificate Section
    private let certSectionLabel: UILabel = {
        let label = UILabel()
        label.text = "🔑 Certificate Management"
        label.font = UIFont.systemFont(ofSize: 18, weight: .bold)
        label.textAlignment = .center
        return label
    }()
    
    private let viewCertButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("📜 View Certificate", for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        button.backgroundColor = .systemGreen
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 10
        return button
    }()
    
    private let viewKeyButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("🔐 View Private Key", for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        button.backgroundColor = .systemPurple
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 10
        return button
    }()
    
    private let deleteButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("🗑️ Delete Certificate", for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        button.backgroundColor = .systemRed
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 10
        return button
    }()
    
    // mTLS Section
    private let mtlsSectionLabel: UILabel = {
        let label = UILabel()
        label.text = "📤 mTLS Requests"
        label.font = UIFont.systemFont(ofSize: 18, weight: .bold)
        label.textAlignment = .center
        return label
    }()
    
    private let endpointTextField: UITextField = {
        let textField = UITextField()
        textField.placeholder = "/api/data"
        textField.text = "/api/data"
        textField.borderStyle = .roundedRect
        textField.autocapitalizationType = .none
        textField.autocorrectionType = .no
        textField.font = UIFont.monospacedSystemFont(ofSize: 14, weight: .regular)
        return textField
    }()
    
    private let sendGETButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("📤 GET", for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        button.backgroundColor = .systemTeal
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 10
        return button
    }()
    
    private let sendPOSTButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("📤 POST", for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        button.backgroundColor = .systemIndigo
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 10
        return button
    }()
    
    private let responseTextView: UITextView = {
        let textView = UITextView()
        textView.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.backgroundColor = UIColor(red: 0.1, green: 0.1, blue: 0.15, alpha: 1.0)
        textView.textColor = .green
        textView.layer.cornerRadius = 10
        textView.isEditable = false
        textView.text = """
        Training Steps:
        
        1. Start the mTLS server on your Mac:
           go run mtls_server.go --generate-certs
           go run mtls_server.go
        
        2. Enter the server URL above
        
        3. Tap "Download Certificate from Server"
        
        4. Send GET/POST requests → Should get 200 OK
        
        5. Configure Burp proxy, send request
           → Should get 403 (Burp strips client cert)
        
        6. Extract cert with Frida, import to Burp
        
        7. Send request through Burp → 200 OK!
        """
        return textView
    }()
    
    private let infoTextView: UITextView = {
        let textView = UITextView()
        textView.font = UIFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        textView.backgroundColor = UIColor(white: 0.95, alpha: 1.0)
        textView.layer.cornerRadius = 10
        textView.isEditable = false
        textView.text = """
        // Keychain Labels for Frida:
        Certificate: "com.keychaindemo.certificate"
        Private Key: "com.keychaindemo.privatekey"
        
        // P12 Password: "training"
        """
        return textView
    }()
    
    private let activityIndicator: UIActivityIndicatorView = {
        let indicator = UIActivityIndicatorView(style: .medium)
        indicator.hidesWhenStopped = true
        return indicator
    }()
    
    // MARK: - Lifecycle
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        setupActions()
        updateStatus()
        setupKeyboardDismissal()
    }
    
    // MARK: - Setup
    
    private func setupUI() {
        view.backgroundColor = .white
        title = "Keychain Demo"
        
        view.addSubview(scrollView)
        scrollView.addSubview(contentView)
        
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        contentView.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            
            contentView.topAnchor.constraint(equalTo: scrollView.topAnchor),
            contentView.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor),
            contentView.trailingAnchor.constraint(equalTo: scrollView.trailingAnchor),
            contentView.bottomAnchor.constraint(equalTo: scrollView.bottomAnchor),
            contentView.widthAnchor.constraint(equalTo: scrollView.widthAnchor)
        ])
        
        let views: [UIView] = [
            titleLabel, descriptionLabel, statusLabel,
            serverSectionLabel, serverURLTextField, downloadCertButton,
            certSectionLabel, viewCertButton, viewKeyButton, deleteButton,
            mtlsSectionLabel, endpointTextField, sendGETButton, sendPOSTButton,
            responseTextView, infoTextView, activityIndicator
        ]
        
        views.forEach {
            $0.translatesAutoresizingMaskIntoConstraints = false
            contentView.addSubview($0)
        }
        
        let padding: CGFloat = 20
        let buttonHeight: CGFloat = 50
        let smallButtonHeight: CGFloat = 44
        
        NSLayoutConstraint.activate([
            // Title and description
            titleLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: padding),
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            titleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            
            descriptionLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 8),
            descriptionLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            descriptionLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            
            statusLabel.topAnchor.constraint(equalTo: descriptionLabel.bottomAnchor, constant: 12),
            statusLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            statusLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            
            // Server Section
            serverSectionLabel.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 20),
            serverSectionLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            serverSectionLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            
            serverURLTextField.topAnchor.constraint(equalTo: serverSectionLabel.bottomAnchor, constant: 10),
            serverURLTextField.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            serverURLTextField.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            serverURLTextField.heightAnchor.constraint(equalToConstant: 44),
            
            downloadCertButton.topAnchor.constraint(equalTo: serverURLTextField.bottomAnchor, constant: 10),
            downloadCertButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            downloadCertButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            downloadCertButton.heightAnchor.constraint(equalToConstant: buttonHeight),
            
            // Certificate Section
            certSectionLabel.topAnchor.constraint(equalTo: downloadCertButton.bottomAnchor, constant: 25),
            certSectionLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            certSectionLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            
            viewCertButton.topAnchor.constraint(equalTo: certSectionLabel.bottomAnchor, constant: 10),
            viewCertButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            viewCertButton.widthAnchor.constraint(equalTo: contentView.widthAnchor, multiplier: 0.5, constant: -padding - 5),
            viewCertButton.heightAnchor.constraint(equalToConstant: smallButtonHeight),
            
            viewKeyButton.topAnchor.constraint(equalTo: certSectionLabel.bottomAnchor, constant: 10),
            viewKeyButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            viewKeyButton.widthAnchor.constraint(equalTo: contentView.widthAnchor, multiplier: 0.5, constant: -padding - 5),
            viewKeyButton.heightAnchor.constraint(equalToConstant: smallButtonHeight),
            
            deleteButton.topAnchor.constraint(equalTo: viewCertButton.bottomAnchor, constant: 10),
            deleteButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            deleteButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            deleteButton.heightAnchor.constraint(equalToConstant: smallButtonHeight),
            
            // mTLS Section
            mtlsSectionLabel.topAnchor.constraint(equalTo: deleteButton.bottomAnchor, constant: 25),
            mtlsSectionLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            mtlsSectionLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            
            endpointTextField.topAnchor.constraint(equalTo: mtlsSectionLabel.bottomAnchor, constant: 10),
            endpointTextField.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            endpointTextField.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            endpointTextField.heightAnchor.constraint(equalToConstant: 40),
            
            sendGETButton.topAnchor.constraint(equalTo: endpointTextField.bottomAnchor, constant: 10),
            sendGETButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            sendGETButton.widthAnchor.constraint(equalTo: contentView.widthAnchor, multiplier: 0.5, constant: -padding - 5),
            sendGETButton.heightAnchor.constraint(equalToConstant: buttonHeight),
            
            sendPOSTButton.topAnchor.constraint(equalTo: endpointTextField.bottomAnchor, constant: 10),
            sendPOSTButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            sendPOSTButton.widthAnchor.constraint(equalTo: contentView.widthAnchor, multiplier: 0.5, constant: -padding - 5),
            sendPOSTButton.heightAnchor.constraint(equalToConstant: buttonHeight),
            
            activityIndicator.centerYAnchor.constraint(equalTo: sendGETButton.centerYAnchor),
            activityIndicator.trailingAnchor.constraint(equalTo: sendGETButton.leadingAnchor, constant: -10),
            
            // Response area
            responseTextView.topAnchor.constraint(equalTo: sendGETButton.bottomAnchor, constant: 20),
            responseTextView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            responseTextView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            responseTextView.heightAnchor.constraint(equalToConstant: 200),
            
            infoTextView.topAnchor.constraint(equalTo: responseTextView.bottomAnchor, constant: 15),
            infoTextView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: padding),
            infoTextView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -padding),
            infoTextView.heightAnchor.constraint(equalToConstant: 100),
            infoTextView.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -padding)
        ])
    }
    
    private func setupActions() {
        downloadCertButton.addTarget(self, action: #selector(downloadCertTapped), for: .touchUpInside)
        viewCertButton.addTarget(self, action: #selector(viewCertificateTapped), for: .touchUpInside)
        viewKeyButton.addTarget(self, action: #selector(viewPrivateKeyTapped), for: .touchUpInside)
        deleteButton.addTarget(self, action: #selector(deleteItemsTapped), for: .touchUpInside)
        sendGETButton.addTarget(self, action: #selector(sendGETTapped), for: .touchUpInside)
        sendPOSTButton.addTarget(self, action: #selector(sendPOSTTapped), for: .touchUpInside)
    }
    
    private func setupKeyboardDismissal() {
        let tapGesture = UITapGestureRecognizer(target: self, action: #selector(dismissKeyboard))
        tapGesture.cancelsTouchesInView = false
        view.addGestureRecognizer(tapGesture)
    }
    
    @objc private func dismissKeyboard() {
        view.endEditing(true)
    }
    
    // MARK: - Actions
    
    @objc private func downloadCertTapped() {
        guard let serverURL = serverURLTextField.text, !serverURL.isEmpty else {
            showAlert(title: "Error", message: "Please enter the server URL")
            return
        }
        
        dismissKeyboard()
        activityIndicator.startAnimating()
        downloadCertButton.isEnabled = false
        
        responseTextView.text = "Downloading certificate from server...\n\(serverURL)/download/client.p12"
        
        KeychainManager.shared.downloadAndImportCertificate(from: serverURL) { [weak self] result in
            DispatchQueue.main.async {
                self?.activityIndicator.stopAnimating()
                self?.downloadCertButton.isEnabled = true
                
                switch result {
                case .success(let message):
                    self?.responseTextView.text = "✅ \(message)\n\nCertificate is now stored in Keychain.\nYou can send mTLS requests!"
                    self?.updateStatus()
                    
                case .failure(let error):
                    self?.responseTextView.text = "❌ Failed to download certificate:\n\n\(error.localizedDescription)\n\nMake sure the server is running:\ngo run mtls_server.go"
                }
            }
        }
    }
    
    @objc private func viewCertificateTapped() {
        if let info = KeychainManager.shared.getCertificateInfo() {
            responseTextView.text = "📜 Certificate Info:\n\n\(info)"
        } else {
            showAlert(title: "Not Found", message: "No certificate found. Download from server first.")
        }
    }
    
    @objc private func viewPrivateKeyTapped() {
        if let info = KeychainManager.shared.getPrivateKeyInfo() {
            responseTextView.text = "🔐 Private Key Info:\n\n\(info)\n\n⚠️ This key can be extracted with Frida!"
        } else {
            showAlert(title: "Not Found", message: "No private key found. Download certificate from server first.")
        }
    }
    
    @objc private func deleteItemsTapped() {
        let alert = UIAlertController(title: "Delete Certificate?", message: "This will remove the certificate and private key from the keychain.", preferredStyle: .alert)
        
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Delete", style: .destructive) { [weak self] _ in
            let _ = KeychainManager.shared.deleteAllItems()
            self?.showAlert(title: "Deleted", message: "Certificate and key removed from Keychain.")
            self?.updateStatus()
            self?.responseTextView.text = "Certificate deleted.\nDownload a new one from the server."
        })
        
        present(alert, animated: true)
    }
    
    @objc private func sendGETTapped() {
        sendRequest(method: "GET")
    }
    
    @objc private func sendPOSTTapped() {
        sendRequest(method: "POST")
    }
    
    private func sendRequest(method: String) {
        guard KeychainManager.shared.identityExists() else {
            showAlert(title: "No Certificate", message: "Please download a certificate from the server first.")
            return
        }
        
        guard let baseURL = serverURLTextField.text, !baseURL.isEmpty else {
            showAlert(title: "Missing URL", message: "Please enter the server URL.")
            return
        }
        
        let endpoint = endpointTextField.text ?? "/api/data"
        let fullURL = baseURL + endpoint
        
        dismissKeyboard()
        activityIndicator.startAnimating()
        sendGETButton.isEnabled = false
        sendPOSTButton.isEnabled = false
        
        responseTextView.text = "[\(method)] Sending request to:\n\(fullURL)\n\nWaiting for response..."
        
        let completion: (Result<(Int, String), Error>) -> Void = { [weak self] result in
            DispatchQueue.main.async {
                self?.activityIndicator.stopAnimating()
                self?.sendGETButton.isEnabled = true
                self?.sendPOSTButton.isEnabled = true
                
                switch result {
                case .success(let (statusCode, body)):
                    let statusEmoji = statusCode == 200 ? "✅" : (statusCode == 403 ? "🚫" : "⚠️")
                    var message = """
                    [\(method)] Response:
                    
                    \(statusEmoji) Status: \(statusCode)
                    
                    Body:
                    \(body)
                    """
                    
                    if statusCode == 403 {
                        message += """
                        
                        ---
                        ⚠️ 403 Forbidden!
                        
                        This means the server rejected the request because:
                        - No valid client certificate was presented
                        - If using Burp, extract the cert with Frida and import it
                        """
                    } else if statusCode == 200 {
                        message += "\n\n🎉 mTLS connection successful!"
                    }
                    
                    self?.responseTextView.text = message
                    
                case .failure(let error):
                    self?.responseTextView.text = """
                    [\(method)] Request failed:
                    
                    ❌ Error: \(error.localizedDescription)
                    
                    ---
                    Common issues:
                    • Server not running
                    • Wrong IP/port
                    • Network not reachable
                    """
                }
            }
        }
        
        if method == "GET" {
            KeychainManager.shared.sendGETRequest(to: fullURL, completion: completion)
        } else {
            let body: [String: Any] = [
                "message": "Hello from KeychainDemo",
                "timestamp": ISO8601DateFormatter().string(from: Date()),
                "device": UIDevice.current.name
            ]
            KeychainManager.shared.sendPOSTRequest(to: fullURL, body: body, completion: completion)
        }
    }
    
    // MARK: - Helpers
    
    private func updateStatus() {
        if KeychainManager.shared.identityExists() {
            statusLabel.text = "Status: ✅ Certificate loaded in Keychain"
            statusLabel.textColor = .systemGreen
        } else {
            statusLabel.text = "Status: ⚠️ No certificate - Download from server"
            statusLabel.textColor = .systemOrange
        }
    }
    
    private func showAlert(title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
}
