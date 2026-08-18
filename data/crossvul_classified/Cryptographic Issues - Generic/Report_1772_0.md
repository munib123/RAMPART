# CrossVul Fix Pair: Cryptographic Issues in javascript
**Pair ID:** 1772_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1772_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```javascript
Lines 108-148 of the vulnerable file.



/**
 * writes an s2k hash based on the inputs.
 * @return {String} Produced key of hashAlgorithm hash length
 */
S2K.prototype.write = function () {
  var bytes = String.fromCharCode(enums.write(enums.s2k, this.type));
  bytes += String.fromCharCode(enums.write(enums.hash, this.algorithm));

  switch (this.type) {
    case 'simple':
      break;
    case 'salted':
      bytes += this.salt;
      break;
    case 'iterated':
      bytes += this.salt;
      bytes += String.fromCharCode(this.c);
      break;
  }

  return bytes;
};

/**
 * Produces a key using the specified passphrase and the defined
 * hashAlgorithm
 * @param {String} passphrase Passphrase containing user input
 * @return {String} Produced key with a length corresponding to
 * hashAlgorithm hash length
 */
S2K.prototype.produce_key = function (passphrase, numBytes) {
  passphrase = util.encode_utf8(passphrase);

  function round(prefix, s2k) {
    var algorithm = enums.write(enums.hash, s2k.algorithm);

    switch (s2k.type) {
      case 'simple':
        return crypto.hash.digest(algorithm, prefix + passphrase);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,6 +125,10 @@
       bytes += this.salt;
       bytes += String.fromCharCode(this.c);
       break;
+    case 'gnu':
+      throw new Error("GNU s2k type not supported.");
+    default:
+      throw new Error("Unknown s2k type.");
   }
 
   return bytes;
@@ -165,6 +169,12 @@
           isp = isp.substr(0, count);
 
         return crypto.hash.digest(algorithm, prefix + isp);
+
+      case 'gnu':
+        throw new Error("GNU s2k type not supported.");
+
+      default:
+        throw new Error("Unknown s2k type.");
     }
   }
 
```
