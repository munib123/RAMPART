# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in javascript
**Pair ID:** 1871_1
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1871_1`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```javascript
Lines 90-130 of the vulnerable file.

    done = function(err, data) {
      if (err) throw err;
      return data;
    };
  }

  if (!jwtString){
    return done(new JsonWebTokenError('jwt must be provided'));
  }

  var parts = jwtString.split('.');

  if (parts.length !== 3){
    return done(new JsonWebTokenError('jwt malformed'));
  }

  if (parts[2].trim() === '' && secretOrPublicKey){
    return done(new JsonWebTokenError('jwt signature is required'));
  }

  var valid;

  try {
    valid = jws.verify(jwtString, secretOrPublicKey);
  } catch (e) {
    return done(e);
  }

  if (!valid)
    return done(new JsonWebTokenError('invalid signature'));

  var payload;

  try {
    payload = this.decode(jwtString);
  } catch(err) {
    return done(err);
  }

  if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
    if (typeof payload.exp !== 'number') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,6 +107,12 @@
     return done(new JsonWebTokenError('jwt signature is required'));
   }
 
+  if (!options.algorithms) {
+    options.algorithms = ~secretOrPublicKey.toString().indexOf('BEGIN CERTIFICATE') ?
+                        [ 'RS256','RS384','RS512','ES256','ES384','ES512' ] :
+                        [ 'HS256','HS384','HS512' ];
+  }
+
   var valid;
 
   try {
@@ -124,6 +130,11 @@
     payload = this.decode(jwtString);
   } catch(err) {
     return done(err);
+  }
+
+  var header = jws.decode(jwtString).header;
+  if (!~options.algorithms.indexOf(header.alg)) {
+    return done(new JsonWebTokenError('invalid signature'));
   }
 
   if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
```
