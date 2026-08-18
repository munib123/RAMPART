# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4643_6
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4643_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 2046-2090 of the vulnerable file.

    ['xwd', ['image/x-xwd', 'image/x-xwindowdump']],
    ['xyz', ['chemical/x-xyz', 'chemical/x-pdb']],
    ['yang', 'application/yang'],
    ['yin', 'application/yin+xml'],
    ['z', ['application/x-compressed', 'application/x-compress']],
    ['zaz', 'application/vnd.zzazz.deck+xml'],
    ['zip', ['application/zip', 'multipart/x-zip', 'application/x-zip-compressed', 'application/x-compressed']],
    ['zir', 'application/vnd.zul'],
    ['zmm', 'application/vnd.handheld-entertainment+xml'],
    ['zoo', 'application/octet-stream'],
    ['zsh', 'text/x-script.zsh']
]);

module.exports = {
    detectMimeType(filename) {
        if (!filename) {
            return defaultMimeType;
        }

        let parsed = path.parse(filename);
        let extension = (parsed.ext.substr(1) || parsed.name || '')
            .split('?')
            .shift()
            .trim()
            .toLowerCase();
        let value = defaultMimeType;

        if (extensions.has(extension)) {
            value = extensions.get(extension);
        }

        if (Array.isArray(value)) {
            return value[0];
        }
        return value;
    },

    detectExtension(mimeType) {
        if (!mimeType) {
            return defaultExtension;
        }
        let parts = (mimeType || '')
            .toLowerCase()
            .trim()
            .split('/');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2063,11 +2063,7 @@
         }
 
         let parsed = path.parse(filename);
-        let extension = (parsed.ext.substr(1) || parsed.name || '')
-            .split('?')
-            .shift()
-            .trim()
-            .toLowerCase();
+        let extension = (parsed.ext.substr(1) || parsed.name || '').split('?').shift().trim().toLowerCase();
         let value = defaultMimeType;
 
         if (extensions.has(extension)) {
@@ -2084,10 +2080,7 @@
         if (!mimeType) {
             return defaultExtension;
         }
-        let parts = (mimeType || '')
-            .toLowerCase()
-            .trim()
-            .split('/');
+        let parts = (mimeType || '').toLowerCase().trim().split('/');
         let rootType = parts.shift().trim();
         let subType = parts.join('/').trim();
 
```
