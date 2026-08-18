# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 120_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `120_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 67-107 of the vulnerable file.

      reason = response.statusText;
    }
    if (!reason) {
      reason = json.error;
    }
    const error = new Error(reason);
    error.response = response;
    throw error;
  });
};

export class TimeoutError extends Error {
  constructor (url, ms, ...params) {
    super(`Call to ${url} timed out after ${ms}ms.`, ...params);
    // Dumb hack to fix `instanceof TimeoutError`
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

const cookiePrefix = 'csrf-token=';
const getCSRFToken = () => document && document.cookie && document.cookie.split(';')
  .map(c => _.trim(c))
  .filter(c => c.startsWith(cookiePrefix))
  .map(c => c.slice(cookiePrefix.length)).pop();

export const coFetch = (url, options = {}, timeout=20000) => {
  const allOptions = _.defaultsDeep({}, initDefaults, options);
  if (allOptions.method !== 'GET') {
    allOptions.headers['X-CSRFToken'] = getCSRFToken();
  }

  // If the URL being requested is absolute (and therefore, not a local request),
  // remove the authorization header to prevent credentials from leaking.
  if (url.indexOf('://') >= 0) {
    delete allOptions.headers.Authorization;
    delete allOptions.headers['X-CSRFToken'];
  }

  // Initiate both the fetch promise and a timeout promise
  return Promise.race([
    fetch(url, allOptions).then(response => validateStatus(response, url)),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,16 +84,14 @@
 }
 
 const cookiePrefix = 'csrf-token=';
-const getCSRFToken = () => document && document.cookie && document.cookie.split(';')
+export const getCSRFToken = () => document && document.cookie && document.cookie.split(';')
   .map(c => _.trim(c))
   .filter(c => c.startsWith(cookiePrefix))
   .map(c => c.slice(cookiePrefix.length)).pop();
 
 export const coFetch = (url, options = {}, timeout=20000) => {
   const allOptions = _.defaultsDeep({}, initDefaults, options);
-  if (allOptions.method !== 'GET') {
-    allOptions.headers['X-CSRFToken'] = getCSRFToken();
-  }
+  allOptions.headers['X-CSRFToken'] = getCSRFToken();
 
   // If the URL being requested is absolute (and therefore, not a local request),
   // remove the authorization header to prevent credentials from leaking.
```
