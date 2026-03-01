package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

const (
	defaultAPIPort = 8443
	downloadDir    = "./download"
	certDir        = "./certs"
	caCertFile     = certDir + "/ca.crt"
	caKeyFile      = certDir + "/ca.key"
	serverCert     = certDir + "/server.crt"
	serverKey      = certDir + "/server.key"
	clientCert     = certDir + "/client.crt"
	clientKey      = certDir + "/client.key"
	clientP12      = downloadDir + "/client.p12"
)

// Response structure for JSON responses
type Response struct {
	Status     string      `json:"status,omitempty"`
	Error      string      `json:"error,omitempty"`
	Message    string      `json:"message,omitempty"`
	Hint       string      `json:"hint,omitempty"`
	Timestamp  string      `json:"timestamp,omitempty"`
	Endpoint   string      `json:"endpoint,omitempty"`
	Method     string      `json:"method,omitempty"`
	ClientCert interface{} `json:"client_cert,omitempty"`
	Data       interface{} `json:"received_data,omitempty"`
	Secret     string      `json:"secret,omitempty"`
	Flag       string      `json:"flag,omitempty"`
	Endpoints  interface{} `json:"endpoints,omitempty"`
}

var caCertPool *x509.CertPool

func getClientCertInfo(r *http.Request) map[string]interface{} {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return map[string]interface{}{"presented": false}
	}

	cert := r.TLS.PeerCertificates[0]
	return map[string]interface{}{
		"presented":   true,
		"subject":     cert.Subject.CommonName,
		"issuer":      cert.Issuer.CommonName,
		"serial":      cert.SerialNumber.String(),
		"not_before":  cert.NotBefore.Format(time.RFC3339),
		"not_after":   cert.NotAfter.Format(time.RFC3339),
		"valid_chain": len(r.TLS.VerifiedChains) > 0,
	}
}

func hasValidClientCert(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.VerifiedChains) > 0
}

func sendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Server", "mTLS-Demo-Server/1.0")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// API handler - requires valid client certificate
func apiHandler(w http.ResponseWriter, r *http.Request) {
	certStatus := "No valid cert"
	if hasValidClientCert(r) {
		cert := r.TLS.PeerCertificates[0]
		certStatus = fmt.Sprintf("Valid cert: %s", cert.Subject.CommonName)
	} else if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		certStatus = "Cert presented but invalid"
	}
	log.Printf("[API] [%s] %s %s [%s]", r.RemoteAddr, r.Method, r.URL.Path, certStatus)

	// Check for valid client certificate
	if !hasValidClientCert(r) {
		sendJSON(w, http.StatusForbidden, Response{
			Error:     "Forbidden",
			Message:   "Valid client certificate required",
			Hint:      "Download the client certificate first, then use Frida to extract it for Burp",
			Timestamp: time.Now().Format(time.RFC3339),
		})
		return
	}

	// Route handling
	switch r.URL.Path {
	case "/", "/api":
		sendJSON(w, http.StatusOK, Response{
			Status:  "success",
			Message: "Welcome to the mTLS Demo Server!",
			Endpoints: map[string]string{
				"GET /api/data":   "Returns sample data",
				"GET /api/secret": "Returns secret data with flag",
				"POST /api/data":  "Accepts and echoes JSON data",
			},
			ClientCert: getClientCertInfo(r),
		})

	case "/api/data":
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			var data interface{}
			if err := json.Unmarshal(body, &data); err != nil {
				data = map[string]string{"raw": string(body)}
			}
			sendJSON(w, http.StatusOK, Response{
				Status:     "success",
				Message:    "POST request successful! 🎉",
				Timestamp:  time.Now().Format(time.RFC3339),
				Endpoint:   r.URL.Path,
				Method:     "POST",
				Data:       data,
				ClientCert: getClientCertInfo(r),
			})
		} else {
			sendJSON(w, http.StatusOK, Response{
				Status:     "success",
				Message:    "GET request successful! 🎉",
				Timestamp:  time.Now().Format(time.RFC3339),
				Endpoint:   r.URL.Path,
				Method:     "GET",
				ClientCert: getClientCertInfo(r),
			})
		}

	case "/api/secret":
		sendJSON(w, http.StatusOK, Response{
			Status:    "success",
			Secret:    "The treasure is buried under the old oak tree 🌳",
			Flag:      "FLAG{mTLS_bypass_successful_congratulations}",
			Timestamp: time.Now().Format(time.RFC3339),
		})

	default:
		sendJSON(w, http.StatusNotFound, Response{
			Error:   "Not Found",
			Message: r.URL.Path,
		})
	}
}

// Download handler - NO client certificate required
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DOWNLOAD] [%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)

	switch r.URL.Path {
	case "/", "/download", "/download/":
		sendJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "success",
			"message": "Certificate Download Server",
			"endpoints": map[string]string{
				"GET /download/client.p12": "Download client certificate bundle",
				"GET /download/info":       "Get download information",
			},
		})

	case "/download/client.p12":
		data, err := os.ReadFile(clientP12)
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, Response{
				Error:   "Certificate not found",
				Message: "Run server with -generate-certs first",
			})
			return
		}
		w.Header().Set("Content-Type", "application/x-pkcs12")
		w.Header().Set("Content-Disposition", "attachment; filename=client.p12")
		w.Header().Set("X-P12-Password", "training")
		w.Write(data)

	case "/download/info":
		sendJSON(w, http.StatusOK, map[string]string{
			"client_p12_url": "/download/client.p12",
			"password":       "training",
			"instructions":   "Download client.p12, import into iOS app, use password 'training'",
		})

	default:
		sendJSON(w, http.StatusNotFound, Response{Error: "Not Found"})
	}
}

func generateCertificates() error {
	fmt.Println("[*] Generating certificates for mTLS server...")

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}

	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return err
	}

	// 1. Generate CA
	fmt.Println("[+] Generating CA...")
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Security Research Training"},
			CommonName:   "Demo CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA cert: %v", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(caCertFile, caCertPEM, 0644); err != nil {
		return err
	}

	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})
	if err := os.WriteFile(caKeyFile, caKeyPEM, 0600); err != nil {
		return err
	}

	caCert, _ := x509.ParseCertificate(caCertDER)

	// 2. Generate Server Certificate
	fmt.Println("[+] Generating server certificate...")
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Security Research Training"},
			CommonName:   "mTLS Demo Server",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverPrivKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create server cert: %v", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	if err := os.WriteFile(serverCert, serverCertPEM, 0644); err != nil {
		return err
	}

	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey)})
	if err := os.WriteFile(serverKey, serverKeyPEM, 0600); err != nil {
		return err
	}

	// 3. Generate Client Certificate
	fmt.Println("[+] Generating client certificate...")
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate client key: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Security Research Training"},
			CommonName:   "Demo Client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientPrivKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create client cert: %v", err)
	}

	clientCertParsed, _ := x509.ParseCertificate(clientCertDER)

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	if err := os.WriteFile(clientCert, clientCertPEM, 0644); err != nil {
		return err
	}

	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey)})
	if err := os.WriteFile(clientKey, clientKeyPEM, 0600); err != nil {
		return err
	}

	// 4. Create PKCS12 bundle for client
	fmt.Println("[+] Creating client.p12 bundle...")
	p12Data, err := pkcs12.LegacyRC2.Encode(clientPrivKey, clientCertParsed, []*x509.Certificate{caCert}, "training")
	if err != nil {
		return fmt.Errorf("failed to create P12: %v", err)
	}

	if err := os.WriteFile(clientP12, p12Data, 0644); err != nil {
		return err
	}

	fmt.Printf(`
[+] Certificates generated successfully!

Files created in %s/:
  - ca.crt / ca.key       (Certificate Authority)
  - server.crt / server.key (Server certificate)
  - client.crt / client.key (Client certificate)

Client certificate saved to:  
  - %s/client.p12              (Client cert + key bundle, password: "training")

To start the server:
  go run mtls_server.go

`, certDir, downloadDir)
	return nil
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func runServer(port int, noVerify bool) {
	// Check certificates exist
	for _, f := range []string{caCertFile, serverCert, serverKey, clientP12} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			log.Fatalf("Required file missing: %s\nRun with -generate-certs first", f)
		}
	}

	// Load CA for client verification
	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	// Load server certificate
	cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		log.Fatalf("Failed to load server cert: %v", err)
	}

	localIP := getLocalIP()

	// TLS configuration
	var tlsConfig *tls.Config
	var modeStr string

	if noVerify {
		// No client certificate verification - for downloading certs
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
		}
		modeStr = "DISABLED (-no-verify mode)"
	} else {
		// Full mTLS - require valid client certificate
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    caCertPool,
		}
		modeStr = "REQUIRED (mTLS enabled)"
	}

	// Single mux handles both download and API
	mux := http.NewServeMux()
	mux.HandleFunc("/download/", downloadHandler)
	mux.HandleFunc("/", apiHandler)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	fmt.Printf(`
╔════════════════════════════════════════════════════════════════════╗
║                    mTLS Demo Server Started                        ║
╠════════════════════════════════════════════════════════════════════╣
║  Server URL:   https://%s:%d                           ║
║  Local URL:    https://localhost:%d                              ║
║                                                                    ║
║  Client Cert:  %-43s         ║
╠════════════════════════════════════════════════════════════════════╣
║  Endpoints:                                                        ║
║    GET  /download/client.p12  - Download client certificate        ║
║    GET  /api/data             - Sample data                        ║
║    GET  /api/secret           - Secret data with flag              ║
║    POST /api/data             - Echo posted data                   ║
╠════════════════════════════════════════════════════════════════════╣
`, localIP, port, port, modeStr)

	if noVerify {
		fmt.Printf(`║  ⚠️  NO-VERIFY MODE: Client certificates NOT required               ║
║      Use this mode to download the certificate to your iOS app     ║
║      Then restart WITHOUT -no-verify for mTLS testing              ║
╠════════════════════════════════════════════════════════════════════╣
`)
	} else {
		fmt.Printf(`║  Training Flow:                                                    ║
║    1. Start with -no-verify, download cert to iOS app              ║
║    2. Restart WITHOUT -no-verify (mTLS enabled)                    ║
║    3. iOS app sends request → 200 OK                               ║
║    4. Through Burp (no cert) → 403 Forbidden                       ║
║    5. Extract cert with Frida, import to Burp → 200 OK             ║
╠════════════════════════════════════════════════════════════════════╣
`)
	}

	fmt.Printf(`║  Press Ctrl+C to stop                                              ║
╚════════════════════════════════════════════════════════════════════╝

`)

	log.Printf("Starting server on :%d (Client cert: %s)", port, modeStr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

func main() {
	port := flag.Int("port", defaultAPIPort, "Server port")
	genCerts := flag.Bool("generate-certs", false, "Generate all certificates")
	noVerify := flag.Bool("no-verify", false, "Disable client certificate verification (for downloading certs)")
	flag.Parse()

	if *genCerts {
		if err := generateCertificates(); err != nil {
			log.Fatal(err)
		}
	} else {
		runServer(*port, *noVerify)
	}
}
