# CrossVul Fix Pair: Improper Authentication in javascript
**Pair ID:** 2895_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2895_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```javascript
Lines 520-560 of the vulnerable file.

    sub.remove(this, path, next);
};


internals.Socket.prototype._authenticate = function () {

    const config = this._listener._settings.auth;
    if (!config) {
        return;
    }

    if (config.timeout) {
        this.auth._timeout = setTimeout(() => this.disconnect(), config.timeout);
    }

    const cookies = this._ws.upgradeReq.headers.cookie;
    if (!cookies) {
        return;
    }

    this._listener._connection.states.parse(cookies, (ignoreErr, state, failed) => {

        const auth = state[config.cookie];
        if (auth) {
            this.auth._error = this._setCredentials(auth.credentials, auth.artifacts);
        }
    });
};


internals.Socket.prototype._setCredentials = function (credentials, artifacts) {

    this.auth.isAuthenticated = true;
    this.auth.credentials = credentials;
    this.auth.artifacts = artifacts;

    return this._listener._sockets.auth(this);
};


internals.Socket.prototype._filterHeaders = function (headers) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -537,7 +537,12 @@
         return;
     }
 
-    this._listener._connection.states.parse(cookies, (ignoreErr, state, failed) => {
+    this._listener._connection.states.parse(cookies, (err, state, failed) => {
+
+        if (err) {
+            this.auth._error = Boom.unauthorized('Invalid nes authentication cookie');
+            return;
+        }
 
         const auth = state[config.cookie];
         if (auth) {
```
