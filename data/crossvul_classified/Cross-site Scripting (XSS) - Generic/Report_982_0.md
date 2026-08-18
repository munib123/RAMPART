# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 982_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `982_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 40-80 of the vulnerable file.

};

// Debug utility to complement console.log
const DEBUG = (() => {
    const timestamp = () => {};
    timestamp.toString = () => `[DEBUG ${moment().format()}]`;

    return {
        log: console.log.bind(console, '%s', timestamp),
    };
})();

// Utility to convert bytes to readable text e.g. "2 KB" or "5 MB"
function bytesToSize(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 Bytes';
    const ii = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)), 10);
    return `${Math.round(bytes / (1024 ** ii), 2)} ${sizes[ii]}`;
}

// Convert cars/vw/golf.png to golf.png
function fullpath2filename(path) {
    return path.replace(/^.*[\\/]/, '');
}

// Convert cars/vw/golf.png to cars/vw/
function fullpath2pathname(path) {
    const index = path.lastIndexOf('/');
    return index === -1 ? '/' : path.substring(0, index + 1);
}

// Convert cars/vw/ to vw/
function prefix2folder(prefix) {
    const parts = prefix.split('/');
    return `${parts[parts.length - 2]}/`;
}

// Convert cars/vw/sedans/ to cars/vw/
function prefix2parentfolder(prefix) {
    const parts = prefix.split('/');
    parts.splice(parts.length - 2, 1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,28 +57,41 @@
     return `${Math.round(bytes / (1024 ** ii), 2)} ${sizes[ii]}`;
 }
 
+// Escape strings of HTML
+function htmlEscape(str) {
+    return str
+        .replace(/&/g, '&amp;')
+        .replace(/</g, '&lt;')
+        .replace(/>/g, '&gt;')
+        .replace(/"/g, '&quot;')
+        .replace(/'/g, '&#39;')
+        .replace(/\//g, '&#x2F;')
+        .replace(/`/g, '&#x60;')
+        .replace(/=/g, '&#x3D;');
+}
+
 // Convert cars/vw/golf.png to golf.png
 function fullpath2filename(path) {
-    return path.replace(/^.*[\\/]/, '');
+    return htmlEscape(path.replace(/^.*[\\/]/, ''));
 }
 
 // Convert cars/vw/golf.png to cars/vw/
 function fullpath2pathname(path) {
     const index = path.lastIndexOf('/');
-    return index === -1 ? '/' : path.substring(0, index + 1);
+    return index === -1 ? '/' : htmlEscape(path.substring(0, index + 1));
 }
 
 // Convert cars/vw/ to vw/
 function prefix2folder(prefix) {
     const parts = prefix.split('/');
-    return `${parts[parts.length - 2]}/`;
+    return htmlEscape(`${parts[parts.length - 2]}/`);
 }
 
 // Convert cars/vw/sedans/ to cars/vw/
 function prefix2parentfolder(prefix) {
     const parts = prefix.split('/');
     parts.splice(parts.length - 2, 1);
-    return parts.join('/');
+    return htmlEscape(parts.join('/'));
 }
 
 // Convert cars/vw/golf.png to  cars/.../golf.png
@@ -89,7 +102,7 @@
     const soft = `${prefix2parentfolder(fullpath2pathname(path)) + pathHellip}/${fullpath2filename(path)}`;
     if (soft.length < pathLimit && soft.length > 2) return soft;
     const hard = `${path.substring(0, path.indexOf('/') + 1) + pathHellip}/${fullpath2filename(path)}`;
-    return hard.length < pathLimit ? hard : path.substring(0, pathLimit) + pathHellip;
+    return hard.length < pathLimit ? htmlEscape(hard) : htmlEscape(path.substring(0, pathLimit) + pathHellip);
 }
 
 // Virtual-hosted-style URL, ex: https://mybucket1.s3.amazonaws.com/index.html
@@ -364,10 +377,11 @@
         const href = object2hrefvirt($scope.view.settings.bucket, data);
 
         function render(d, href2, text, download) {
+            const d2 = htmlEscape(d);
             if (download) {
-                return `<a data-s3="object" data-s3key="${d}" href="${href2}" download="${download}">${text}</a>`;
-            }
-            return `<a data-s3="folder" data-s3key="${d}" href="${href2}">${text}</a>`;
+                return `<a data-s3="object" data-s3key="${d2}" href="${href2}" download="${download}">${text}</a>`;
+            }
+            return `<a data-s3="folder" data-s3key="${d2}" href="${href2}">${text}</a>`;
         }
 
         if (full.CommonPrefix) {
```
