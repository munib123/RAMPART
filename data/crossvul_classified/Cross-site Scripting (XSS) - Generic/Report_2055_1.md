# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2055_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2055_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 41-78 of the vulnerable file.

         * @param {Function} fn The function to store
         * @namespace easyXDM.fn
         */
        set: function(name, fn){
            // #ifdef debug
            this._trace("storing function " + name);
            // #endif
            _map[name] = fn;
        },
        /**
         * Retrieves the function referred to by the given name
         * @param {String} name The name of the function to retrieve
         * @param {Boolean} del If the function should be deleted after retrieval
         * @return {Function} The stored function
         * @namespace easyXDM.fn
         */
        get: function(name, del){
            // #ifdef debug
            this._trace("retrieving function " + name);
            // #endif
            var fn = _map[name];
            // #ifdef debug
            if (!fn) {
                this._trace(name + " not found");
            }
            // #endif
            
            if (del) {
                delete _map[name];
            }
            return fn;
        }
    };
    
    // #ifdef debug
    easyXDM.Fn._trace = debug.getTracer("easyXDM.Fn");
    // #endif
}());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,6 +58,9 @@
             // #ifdef debug
             this._trace("retrieving function " + name);
             // #endif
+            if (!_map.hasOwnProperty(name)) {
+                return;
+            }
             var fn = _map[name];
             // #ifdef debug
             if (!fn) {
```
