# CrossVul Fix Pair: Origin Validation Error in javascript
**Pair ID:** 2992_4
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2992_4`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```javascript
Lines 25-65 of the vulnerable file.

  confirmRequest (requestId, options, password) {
    return this._transport
      .execute('signer_confirmRequest', inNumber16(requestId), inOptions(options), password);
  }

  confirmRequestRaw (requestId, data) {
    return this._transport
      .execute('signer_confirmRequestRaw', inNumber16(requestId), inData(data));
  }

  confirmRequestWithToken (requestId, options, password) {
    return this._transport
      .execute('signer_confirmRequestWithToken', inNumber16(requestId), inOptions(options), password);
  }

  generateAuthorizationToken () {
    return this._transport
      .execute('signer_generateAuthorizationToken');
  }

  generateWebProxyAccessToken () {
    return this._transport
      .execute('signer_generateWebProxyAccessToken');
  }

  rejectRequest (requestId) {
    return this._transport
      .execute('signer_rejectRequest', inNumber16(requestId));
  }

  requestsToConfirm () {
    return this._transport
      .execute('signer_requestsToConfirm')
      .then((requests) => (requests || []).map(outSignerRequest));
  }

  signerEnabled () {
    return this._transport
      .execute('signer_signerEnabled');
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,9 +42,9 @@
       .execute('signer_generateAuthorizationToken');
   }
 
-  generateWebProxyAccessToken () {
+  generateWebProxyAccessToken (domain) {
     return this._transport
-      .execute('signer_generateWebProxyAccessToken');
+      .execute('signer_generateWebProxyAccessToken', domain);
   }
 
   rejectRequest (requestId) {
```
