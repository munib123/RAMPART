# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 3327_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3327_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 265-305 of the vulnerable file.

        enableExtension(uuid);
    });

    // Find and disable all the newly disabled extensions: UUIDs found in the
    // old setting, but not in the new one.
    enabledExtensions.filter(function(item) {
        return newEnabledExtensions.indexOf(item) == -1;
    }).forEach(function(uuid) {
        disableExtension(uuid);
    });

    enabledExtensions = newEnabledExtensions;
}

function _onVersionValidationChanged() {
    // we want to reload all extensions, but only enable
    // extensions when allowed by the sessionMode, so
    // temporarily disable them all
    enabledExtensions = [];
    for (let uuid in ExtensionUtils.extensions)
        reloadExtension(ExtensionUtils.extensions[uuid]);
    enabledExtensions = getEnabledExtensions();

    if (Main.sessionMode.allowExtensions) {
        enabledExtensions.forEach(function(uuid) {
            enableExtension(uuid);
        });
    }
}

function _loadExtensions() {
    global.settings.connect('changed::' + ENABLED_EXTENSIONS_KEY, onEnabledExtensionsChanged);
    global.settings.connect('changed::' + DISABLE_USER_EXTENSIONS_KEY, onEnabledExtensionsChanged);
    global.settings.connect('changed::' + EXTENSION_DISABLE_VERSION_CHECK_KEY, _onVersionValidationChanged);

    enabledExtensions = getEnabledExtensions();

    let finder = new ExtensionUtils.ExtensionFinder();
    finder.connect('extension-found', function(finder, extension) {
        loadExtension(extension);
    });
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -282,12 +282,20 @@
     // temporarily disable them all
     enabledExtensions = [];
     for (let uuid in ExtensionUtils.extensions)
-        reloadExtension(ExtensionUtils.extensions[uuid]);
+        try {
+            reloadExtension(ExtensionUtils.extensions[uuid]);
+        } catch(e) {
+            logExtensionError(uuid, e);
+        }
     enabledExtensions = getEnabledExtensions();
 
     if (Main.sessionMode.allowExtensions) {
         enabledExtensions.forEach(function(uuid) {
-            enableExtension(uuid);
+            try {
+                enableExtension(uuid);
+            } catch(e) {
+                logExtensionError(uuid, e);
+            }
         });
     }
 }
```
