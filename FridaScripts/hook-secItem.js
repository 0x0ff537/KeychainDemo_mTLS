if (ObjC.available) {

    // Find Security framework exports
    var modules = Process.enumerateModules();
    var securityModule = null;
    var SecItemCopyMatchingAddr = null;
    
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
    }

    var exports = securityModule.enumerateExports();
    for (var i = 0; i < exports.length; i++) {
        if(exports[i].name === "SecItemCopyMatching"){
            SecItemCopyMatchingAddr = exports[i].address;
            console.log("[+] SecItemCopyMatching is at " + SecItemCopyMatchingAddr);
            break;
        }
    }

    // Hook SecItemCopyMatching
    var SecItemCopyMatching = new NativeFunction(SecItemCopyMatchingAddr, 'int', ['pointer', 'pointer']);
    
    Interceptor.attach(SecItemCopyMatchingAddr, {
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
}
