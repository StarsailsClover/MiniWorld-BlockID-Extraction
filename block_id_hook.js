// Frida script to extract MiniWorld block IDs at runtime
// Run with: frida -U -f com.minitech.miniworld -l block_id_hook.js --no-pause

console.log("[*] MiniWorld Block ID Extractor");
console.log("[*] Waiting for block-related functions...");

// Common patterns for block ID functions in Unity games
var moduleNames = ["libunity.so", "libil2cpp.so", "libmain.so"];

function findBlockFunctions() {
    var found = [];
    
    moduleNames.forEach(function(name) {
        try {
            var module = Process.findModuleByName(name);
            if (module) {
                console.log("[+] Found module: " + name + " at " + module.base);
                
                // Search for common block function patterns
                var patterns = [
                    "getBlockId", "GetBlockId", "get_BlockId",
                    "setBlock", "SetBlock", "placeBlock",
                    "Block::getId", "Block::GetId",
                    "Terrain::get", "World::getBlock"
                ];
                
                patterns.forEach(function(p) {
                    try {
                        var exports = Module.enumerateExports(name);
                        exports.forEach(function(exp) {
                            if (exp.name && exp.name.toLowerCase().includes(p.toLowerCase())) {
                                console.log("  [+] Found: " + exp.name + " at " + exp.address);
                                found.push({name: exp.name, address: exp.address});
                            }
                        });
                    } catch(e) {}
                });
            }
        } catch(e) {}
    });
    
    return found;
}

// Hook found functions
function hookBlockFunctions(functions) {
    functions.forEach(function(func) {
        try {
            Interceptor.attach(func.address, {
                onEnter: function(args) {
                    console.log("[*] " + func.name + " called");
                    console.log("    arg0: " + args[0]);
                    console.log("    arg1: " + args[1]);
                    console.log("    arg2: " + args[2]);
                },
                onLeave: function(retval) {
                    console.log("    returned: " + retval);
                }
            });
            console.log("[+] Hooked: " + func.name);
        } catch(e) {
            console.log("[-] Failed to hook " + func.name + ": " + e);
        }
    });
}

// Main
setTimeout(function() {
    var functions = findBlockFunctions();
    console.log("[*] Found " + functions.length + " potential block functions");
    hookBlockFunctions(functions);
}, 1000);

// Alternative: Hook JNI calls for block operations
Java.perform(function() {
    console.log("[*] Java runtime ready");
    
    // Look for block-related Java classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.toLowerCase().includes('block') || 
                className.toLowerCase().includes('terrain') ||
                className.toLowerCase().includes('world')) {
                console.log("[Class] " + className);
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration complete");
        }
    });
});