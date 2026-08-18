# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in javascript
**Pair ID:** 1429_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1429_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```javascript
Lines 92-150 of the vulnerable file.


  this.verified = null;
  this.revoked = null;
}

/**
 * parsing function for a signature packet (tag 2).
 * @param {String} bytes payload of a tag 2 packet
 * @param {Integer} position position to start reading from the bytes string
 * @param {Integer} len length of the packet or the remaining length of bytes at position
 * @returns {module:packet.Signature} object representation
 */
Signature.prototype.read = function (bytes) {
  let i = 0;
  this.version = bytes[i++];

  if (this.version !== 4) {
    throw new Error('Version ' + this.version + ' of the signature is unsupported.');
  }

  const subpackets = bytes => {
    // Two-octet scalar octet count for following subpacket data.
    const subpacket_length = util.readNumber(bytes.subarray(0, 2));

    let i = 2;

    // subpacket data set (zero or more subpackets)
    while (i < 2 + subpacket_length) {
      const len = packet.readSimpleLength(bytes.subarray(i, bytes.length));
      i += len.offset;

      this.read_sub_packet(bytes.subarray(i, i + len.len));

      i += len.len;
    }

    return i;
  };

  this.signatureType = bytes[i++];
  this.publicKeyAlgorithm = bytes[i++];
  this.hashAlgorithm = bytes[i++];

  // hashed subpackets
  i += subpackets(bytes.subarray(i, bytes.length), true);

  // A V4 signature hashes the packet body
  // starting from its first field, the version number, through the end
  // of the hashed subpacket data.  Thus, the fields hashed are the
  // signature version, the signature type, the public-key algorithm, the
  // hash algorithm, the hashed subpacket length, and the hashed
  // subpacket body.
  this.signatureData = bytes.subarray(0, i);
  const sigDataLength = i;

  // unhashed subpackets
  i += subpackets(bytes.subarray(i, bytes.length), false);
  this.unhashedSubpackets = bytes.subarray(sigDataLength, i);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,31 +109,12 @@
     throw new Error('Version ' + this.version + ' of the signature is unsupported.');
   }
 
-  const subpackets = bytes => {
-    // Two-octet scalar octet count for following subpacket data.
-    const subpacket_length = util.readNumber(bytes.subarray(0, 2));
-
-    let i = 2;
-
-    // subpacket data set (zero or more subpackets)
-    while (i < 2 + subpacket_length) {
-      const len = packet.readSimpleLength(bytes.subarray(i, bytes.length));
-      i += len.offset;
-
-      this.read_sub_packet(bytes.subarray(i, i + len.len));
-
-      i += len.len;
-    }
-
-    return i;
-  };
-
   this.signatureType = bytes[i++];
   this.publicKeyAlgorithm = bytes[i++];
   this.hashAlgorithm = bytes[i++];
 
   // hashed subpackets
-  i += subpackets(bytes.subarray(i, bytes.length), true);
+  i += this.read_sub_packets(bytes.subarray(i, bytes.length), true);
 
   // A V4 signature hashes the packet body
   // starting from its first field, the version number, through the end
@@ -145,7 +126,7 @@
   const sigDataLength = i;
 
   // unhashed subpackets
-  i += subpackets(bytes.subarray(i, bytes.length), false);
+  i += this.read_sub_packets(bytes.subarray(i, bytes.length), false);
   this.unhashedSubpackets = bytes.subarray(sigDataLength, i);
 
   // Two-octet field holding left 16 bits of signed hash value.
@@ -346,7 +327,7 @@
 
 // V4 signature sub packets
 
-Signature.prototype.read_sub_packet = function (bytes) {
+Signature.prototype.read_sub_packet = function (bytes, trusted=true) {
   let mypos = 0;
 
   const read_array = (prop, bytes) => {
@@ -359,6 +340,17 @@
 
   // The leftwost bit denotes a "critical" packet, but we ignore it.
   const type = bytes[mypos++] & 0x7F;
+
+  // GPG puts the Issuer and Signature subpackets in the unhashed area.
+  // Tampering with those invalidates the signature, so we can trust them.
+  // Ignore all other unhashed subpackets.
+  if (!trusted && ![
+    enums.signatureSubpacket.issuer,
+    enums.signatureSubpacket.embedded_signature
+  ].includes(type)) {
+    return;
+  }
+
   let seconds;
 
   // subpacket type
@@ -513,6 +505,25 @@
     default:
       util.print_debug("Unknown signature subpacket type " + type + " @:" + mypos);
   }
+};
+
+Signature.prototype.read_sub_packets = function(bytes, trusted=true) {
+  // Two-octet scalar octet count for following subpacket data.
+  const subpacket_length = util.readNumber(bytes.subarray(0, 2));
+
+  let i = 2;
+
+  // subpacket data set (zero or more subpackets)
+  while (i < 2 + subpacket_length) {
+    const len = packet.readSimpleLength(bytes.subarray(i, bytes.length));
+    i += len.offset;
+
+    this.read_sub_packet(bytes.subarray(i, i + len.len), trusted);
+
+    i += len.len;
+  }
+
+  return i;
 };
 
 // Produces data to produce signature on
```
