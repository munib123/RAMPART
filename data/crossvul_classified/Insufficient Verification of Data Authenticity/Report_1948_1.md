# CrossVul Fix Pair: Insufficient Verification of Data Authenticity in javascript
**Pair ID:** 1948_1
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-345
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1948_1`)

## Vulnerability Information & PoC

## Description
Insufficient Verification of Data Authenticity - The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

const params = window.location.search.substring(1).split('&');
let lockOrigin;
for (let i = 0; i < params.length; ++i) {
    const parts = params[i].split('=');
    if (parts[0] === 'origin') lockOrigin = decodeURIComponent(parts[1]);
}

function remoteRender(event) {
    const data = event.data;

    const img = document.createElement("img");
    img.id = "img";
    img.src = data.imgSrc;
    img.style = data.imgStyle;

    const a = document.createElement("a");
    a.id = "a";
    a.rel = "noreferrer noopener";
    a.download = data.download;
    a.style = data.style;
    a.style.fontFamily = "Arial, Helvetica, Sans-Serif";
    a.href = window.URL.createObjectURL(data.blob);
    a.appendChild(img);
    a.appendChild(document.createTextNode(data.textContent));

    const body = document.body;
    // Don't display scrollbars if the link takes more than one line to display.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,10 +1,3 @@
-const params = window.location.search.substring(1).split('&');
-let lockOrigin;
-for (let i = 0; i < params.length; ++i) {
-    const parts = params[i].split('=');
-    if (parts[0] === 'origin') lockOrigin = decodeURIComponent(parts[1]);
-}
-
 function remoteRender(event) {
     const data = event.data;
 
@@ -45,7 +38,7 @@
 }
 
 window.onmessage = function(e) {
-    if (e.origin === lockOrigin) {
+    if (e.origin === window.location.origin) {
         if (e.data.blob) remoteRender(e);
         else remoteSetTint(e);
     }
```
