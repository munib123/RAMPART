# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 120_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `120_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

/**
 * @fileOverview
 * WebSocket factory and utility wrapper.
 *
 */
/* eslint-disable no-console */

function createURL(host, path) {
  let url;

  if (host === 'auto') {
    if (location.protocol === 'https:') {
      url = 'wss://';
    } else {
      url = 'ws://';
    }
    url += location.host;
  } else {
    url = host;
  }

  if (path) {
    url += path;
  }
  return url;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,15 @@
  */
 /* eslint-disable no-console */
 
+import { getCSRFToken } from '../co-fetch';
+
+function addCSRFQueryParam(href) {
+  const url = new URL(href);
+  const csrfToken = getCSRFToken();
+  url.searchParams.set('x-csrf-token', csrfToken);
+  return url.href;
+}
+
 function createURL(host, path) {
   let url;
 
@@ -22,7 +31,8 @@
   if (path) {
     url += path;
   }
-  return url;
+
+  return addCSRFQueryParam(url);
 }
 
 export function WSFactory(id, options) {
```
