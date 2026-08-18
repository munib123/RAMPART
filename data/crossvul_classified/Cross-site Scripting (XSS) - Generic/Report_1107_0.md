# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1107_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1107_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1702-1742 of the vulnerable file.

    var span = document.createElement('span');
    if (hs.text)
        span.innerHTML = escapeHTML(hs.text);

    var a;
    if (hs.video) {
        var video = document.createElement('video'),
            vidp = hs.video;
        if (config.basePath && !absoluteURL(vidp))
            vidp = config.basePath + vidp;
        video.src = sanitizeURL(vidp);
        video.controls = true;
        video.style.width = hs.width + 'px';
        renderContainer.appendChild(div);
        span.appendChild(video);
    } else if (hs.image) {
        var imgp = hs.image;
        if (config.basePath && !absoluteURL(imgp))
            imgp = config.basePath + imgp;
        a = document.createElement('a');
        a.href = sanitizeURL(hs.URL ? hs.URL : imgp);
        a.target = '_blank';
        span.appendChild(a);
        var image = document.createElement('img');
        image.src = sanitizeURL(imgp);
        image.style.width = hs.width + 'px';
        image.style.paddingTop = '5px';
        renderContainer.appendChild(div);
        a.appendChild(image);
        span.style.maxWidth = 'initial';
    } else if (hs.URL) {
        a = document.createElement('a');
        a.href = sanitizeURL(hs.URL);
        if (hs.attributes) {
            for (var key in hs.attributes) {
                a.setAttribute(key, hs.attributes[key]);
            }
        } else {
            a.target = '_blank';
        }
        renderContainer.appendChild(a);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1719,7 +1719,7 @@
         if (config.basePath && !absoluteURL(imgp))
             imgp = config.basePath + imgp;
         a = document.createElement('a');
-        a.href = sanitizeURL(hs.URL ? hs.URL : imgp);
+        a.href = sanitizeURL(hs.URL ? hs.URL : imgp, true);
         a.target = '_blank';
         span.appendChild(a);
         var image = document.createElement('img');
@@ -1731,7 +1731,7 @@
         span.style.maxWidth = 'initial';
     } else if (hs.URL) {
         a = document.createElement('a');
-        a.href = sanitizeURL(hs.URL);
+        a.href = sanitizeURL(hs.URL, true);
         if (hs.attributes) {
             for (var key in hs.attributes) {
                 a.setAttribute(key, hs.attributes[key]);
@@ -2005,7 +2005,7 @@
                 var authorText = escapeHTML(config[key]);
                 if (config.authorURL) {
                     var authorLink = document.createElement('a');
-                    authorLink.href = sanitizeURL(config['authorURL']);
+                    authorLink.href = sanitizeURL(config['authorURL'], true);
                     authorLink.target = '_blank';
                     authorLink.innerHTML = escapeHTML(config[key]);
                     authorText = authorLink.outerHTML;
@@ -2016,7 +2016,7 @@
             
             case 'fallback':
                 var link = document.createElement('a');
-                link.href = sanitizeURL(config[key]);
+                link.href = sanitizeURL(config[key], true);
                 link.target = '_blank';
                 link.textContent = 'Click here to view this panorama in an alternative viewer.';
                 var message = document.createElement('p');
@@ -2378,10 +2378,17 @@
  * The URL cannot be of protocol 'javascript'.
  * @private
  * @param {string} url - URL to sanitize
+ * @param {boolean} href - True if URL is for link (blocks data URIs)
  * @returns {string} Sanitized URL
  */
-function sanitizeURL(url) {
-    if (url.trim().toLowerCase().indexOf('javascript:') === 0) {
+function sanitizeURL(url, href) {
+    if (url.trim().toLowerCase().indexOf('javascript:') === 0 ||
+        url.trim().toLowerCase().indexOf('vbscript:') === 0) {
+        console.log('Script URL removed.');
+        return 'about:blank';
+    }
+    if (href && url.trim().toLowerCase().indexOf('data:') === 0) {
+        console.log('Data URI removed from link.');
         return 'about:blank';
     }
     return url;
```
