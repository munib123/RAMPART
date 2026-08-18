# CrossVul Fix Pair: Out-of-bounds Read in javascript
**Pair ID:** 4259_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4259_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```javascript
Lines 2108-2129 of the vulnerable file.

  p = new Proxy(p, {});
}
assert.equal(p.a, 1);

// Test HermesInternal
assert.equal(
  typeof HermesInternal !== 'object' ||
    HermesInternal.isProxy(new Proxy({}, {})),
  true);

// spread of a callable
var f = function() { return 1; }
f.a = 1;
f.b = 2;
checkDeep({...f})(_ => ({a:1, b:2}))

// Check that defining a property in a Proxy target which is an array
// uses fast array access (this will trip an assert otherwise)
new Proxy([], {}).unshift(0);

print('done');
// CHECK-LABEL: done
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2125,5 +2125,14 @@
 // uses fast array access (this will trip an assert otherwise)
 new Proxy([], {}).unshift(0);
 
+// If putComputed is called on a proxy whose target's prototype is an
+// array with a propname of 'length', then internalSetter will be
+// true, and the receiver will be a proxy.  In that case, proxy needs
+// to win; the behavior may assert or be UB otherwise.
+var p = new Proxy(Object.create([]), {});
+// using String() forces putComputed
+p[String('length')] = 0x123;
+p[0xABC] = 1111;
+
 print('done');
 // CHECK-LABEL: done
```
