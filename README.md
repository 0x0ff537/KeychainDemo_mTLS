# Dumping Private Key from Keychain

This repo is supplementary to this blog post. It includes the iOS app and the GoLang server used as a demo. You can run them yourself pretty easily and practice dumping secrets from the iOS Keychain. Feel free to modify the source to your own needs and experiment as much as you wish. Keep learning, keep hacking!

## Quick Start

### 1. Clone this Repositorie

```bash
git clone https://github.com/0x0ff537/KeychainDemo_mTLS
```

### 2. Start the Server (on your host machine)

```bash
cd Server

# Install Go dependencies
go mod tidy

# Generate all certificates (CA, server, client)
go run mtls_server.go --generate-certs

# Start server WITHOUT client cert verification (to download cert)
go run mtls_server.go --no-verify
```

### 3. Download Certificate to iOS App

1. Download (or compile) the iOS app.
2. Open the iOS app.
3. Enter the server URL (e.g., `https://192.168.1.100:8443`).
4. Tap **"Download Certificate from Server"**.
5. Verify status shows "Certificate loaded."

### 4. Restart Server WITH mTLS

```bash
# Stop the server (Ctrl+C), then restart WITHOUT --no-verify
go run mtls_server.go
```

### 5. Test mTLS

1. In iOS app, tap **"GET"** or **"POST"**
2. Should receive **200 OK** ✅

## Testing Scenario

### Phase 1: Direct Connection (Working)

```
iOS App ──────────────────────▶ Server
         (with client cert)
         
Result: 200 OK ✅
```

### Phase 2: Through Burp (Broken)

```
iOS App ────▶ Burp ────▶ Server
              │
              └─ Terminates TLS
                 Doesn't forward client cert
         
Result: 403 Forbidden 🚫
```

### Phase 3: Extract and Import (Fixed)

```
1. Extract cert/key from iOS Keychain using Frida
2. Convert to PKCS12
3. Import into Burp
4. Burp now presents client cert to server

iOS App ────▶ Burp ────▶ Server
              │
              └─ Forwards client cert
         
Result: 200 OK ✅
```

## Detailed Walkthrough

### Step 1: Start Server and Download Certificate

```bash
# Terminal 1: Start server
cd Server
go run mtls_server.go --generate-certs
go run mtls_server.go
```

In iOS app:
1. Enter server URL (e.g., `https://192.168.1.100:8443`)
2. Tap **"Download Certificate from Server"**
3. Verify status shows "Certificate loaded"

### Step 2: Verify Direct Connection Works

1. Tap **"GET"** button
2. Should see **200 OK** with JSON response
3. Server log shows: `[Valid cert: Demo Client]`

### Step 3: Configure Burp Proxy

1. Set Burp as proxy on your Mac
2. Configure iOS device to use Burp proxy
3. Install Burp CA certificate on iOS device

### Step 4: Observe the 403

1. Send request through Burp
2. Burp intercepts the request
3. Server returns **403 Forbidden**
4. This is because Burp doesn't forward the client certificate

### Step 5: Extract Certificate with Frida

```bash
# Attach to the app
frida -U com.securityresearch.keychaindemo -l FridaScripts/extract-keychain-demo.js

# In Frida REPL:
rpc.exports.extractall()
```

### Step 6: Pull and Convert Certificates

```bash
# Pull from device
scp mobile@<device_ip>:/var/tmp/demo_cert.der .
scp mobile@<device_ip>:/var/tmp/demo_key.der .

# Convert to PEM
openssl x509 -inform DER -in demo_cert.der -out demo_cert.pem
openssl rsa -inform DER -in demo_key.der -out demo_key.pem

# Create PKCS12 for Burp
openssl pkcs12 -export -out demo_cert.p12 -inkey demo_key.pem -in demo_cert.pem -passout pass:demoApp
```

### Step 7: Import into Burp

1. Burp → Settings → Network → TLS
2. Client TLS Certificates → Add
3. Destination host: `192.168.1.100` (your server IP)
4. Certificate: Select `demo_cert.p12`
5. Password: `demoApp`

### Step 8: Success!

1. Send request through Burp again
2. Server returns **200 OK** ✅
3. You can now intercept and modify mTLS traffic!

## Server Endpoints

| Endpoint | Auth Required | Description |
|----------|---------------|-------------|
| `GET /api/data` | Yes | Sample data |
| `POST /api/data` | Yes | Echo posted data |
| `GET /api/secret` | Yes | Secret data with flag |

## Security Notes

This is intentionally vulnerable for training:
- Private keys are extractable (not in Secure Enclave)
- No jailbreak detection
- No certificate pinning
- P12 password is simple ("training")

In production apps:
1. Use Secure Enclave (`kSecAttrTokenIDSecureEnclave`)
2. Implement jailbreak/root detection
3. Add certificate pinning
4. Generate keys on-device (never transmit private keys)

## License

MIT License - For educational and security research purposes only.
