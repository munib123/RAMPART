# CrossVul Fix Pair: Origin Validation Error in javascript
**Pair ID:** 2992_6
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2992_6`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```javascript
Lines 42-83 of the vulnerable file.

    this.nextUrl = this.currentUrl = this.loadLastUrl();
  }

  @computed get encodedPath () {
    return `${this._api.dappsUrl}/web/${encodePath(this.token, this.currentUrl)}?t=${this.counter}`;
  }

  @computed get encodedUrl () {
    return `http://${encodeUrl(this.token, this.currentUrl)}:${this._api.dappsPort}?t=${this.counter}`;
  }

  @computed get frameId () {
    return `_web_iframe_${this.counter}`;
  }

  @computed get isPristine () {
    return this.currentUrl === this.nextUrl;
  }

  @action gotoUrl = (_url) => {
    transaction(() => {
      let url = (_url || this.nextUrl).trim().replace(/\/+$/, '');

      if (!hasProtocol.test(url)) {
        url = `https://${url}`;
      }

      this.setNextUrl(url);
      this.setCurrentUrl(this.nextUrl);
    });
  }

  @action reload = () => {
    transaction(() => {
      this.setLoading(true);
      this.counter = Date.now();
    });
  }

  @action restoreUrl = () => {
    this.setNextUrl(this.currentUrl);
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,15 +59,17 @@
   }
 
   @action gotoUrl = (_url) => {
-    transaction(() => {
-      let url = (_url || this.nextUrl).trim().replace(/\/+$/, '');
+    let url = (_url || this.nextUrl).trim().replace(/\/+$/, '');
 
-      if (!hasProtocol.test(url)) {
-        url = `https://${url}`;
-      }
+    if (!hasProtocol.test(url)) {
+      url = `https://${url}`;
+    }
 
-      this.setNextUrl(url);
-      this.setCurrentUrl(this.nextUrl);
+    return this.generateToken(url).then(() => {
+      transaction(() => {
+        this.setNextUrl(url);
+        this.setCurrentUrl(this.nextUrl);
+      });
     });
   }
 
@@ -134,11 +136,11 @@
     this.nextUrl = url;
   }
 
-  generateToken = () => {
+  generateToken = (_url) => {
     this.setToken(null);
 
     return this._api.signer
-      .generateWebProxyAccessToken()
+      .generateWebProxyAccessToken(_url)
       .then((token) => {
         this.setToken(token);
       })
```
