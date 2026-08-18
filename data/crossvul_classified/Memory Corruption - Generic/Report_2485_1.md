# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in javascript
**Pair ID:** 2485_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2485_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```javascript
Lines 1-25 of the vulnerable file.

//-------------------------------------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE.txt file in the project root for full license information.
//-------------------------------------------------------------------------------------------------------

var count = 0;
class A {
    constructor() { count++; }
    increment() { count++; }
}
class B extends A {
    constructor() {
        super();
        ((B) => { super.increment() })();
        (A=> { super.increment() })();
        let C = async (B) => { B };
        let D = async A => { A };
    }
}
let b = new B();
if (count !== 3) {
    WScript.Echo('fail');
}

WScript.Echo('pass');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,7 +18,14 @@
     }
 }
 let b = new B();
-if (count !== 3) {
+class async extends A {
+    constructor() {
+        super();
+        let Q = async A => { A };
+    }
+}
+let a = new async();
+if (count !== 4) {
     WScript.Echo('fail');
 }
 
```
