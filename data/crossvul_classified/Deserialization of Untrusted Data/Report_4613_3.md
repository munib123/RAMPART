# CrossVul Fix Pair: Deserialization of Untrusted Data in javascript
**Pair ID:** 4613_3
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4613_3`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

/* global describe, it, beforeEach */
'use strict';

var serialize = require('../../'),
    expect    = require('chai').expect;

describe('serialize( obj )', function () {
    it('should be a function', function () {
        expect(serialize).to.be.a('function');
    });

    describe('undefined', function () {
        it('should serialize `undefined` to a string', function () {
            expect(serialize()).to.be.a('string').equal('undefined');
            expect(serialize(undefined)).to.be.a('string').equal('undefined');
        });

        it('should deserialize "undefined" to `undefined`', function () {
            expect(eval(serialize())).to.equal(undefined);
            expect(eval(serialize(undefined))).to.equal(undefined);
        });
    });

    describe('null', function () {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,22 @@
 /* global describe, it, beforeEach */
 'use strict';
 
+// temporarily monkeypatch `crypto.randomBytes` so we'll have a
+// predictable UID for our tests
+var crypto = require('crypto');
+var oldRandom = crypto.randomBytes;
+crypto.randomBytes = function(len, cb) {
+    var buf = Buffer.alloc(len);
+    buf.fill(0x00);
+    if (cb)
+        cb(null, buf);
+    return buf;
+};
+
 var serialize = require('../../'),
     expect    = require('chai').expect;
+
+crypto.randomBytes = oldRandom;
 
 describe('serialize( obj )', function () {
     it('should be a function', function () {
@@ -493,4 +507,17 @@
             expect(serialize([1], 2)).to.equal('[\n  1\n]');
         });
     });
+
+    describe('placeholders', function() {
+        it('should not be replaced within string literals', function () {
+            // Since we made the UID deterministic this should always be the placeholder
+            var fakePlaceholder = '"@__R-0000000000000000-0__@';
+            var serialized = serialize({bar: /1/i, foo: fakePlaceholder}, {uid: 'foo'});
+            var obj = eval('(' + serialized + ')');
+            expect(obj).to.be.a('Object');
+            expect(obj.foo).to.be.a('String');
+            expect(obj.foo).to.equal(fakePlaceholder);
+        });
+    });
+
 });
```
