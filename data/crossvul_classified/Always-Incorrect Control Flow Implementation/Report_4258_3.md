# CrossVul Fix Pair: Always-Incorrect Control Flow Implementation in javascript
**Pair ID:** 4258_3
**Vulnerability Class:** Always-Incorrect Control Flow Implementation
**CWE:** CWE-670
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4258_3`)

## Vulnerability Information & PoC

## Description
Always-Incorrect Control Flow Implementation - This weakness captures cases in which a particular code segment is always incorrect with respect to the algorithm that it is implementing.

## Vulnerable Code
```javascript
Lines 337-356 of the vulnerable file.

  },
  get return() {
    print('get return');
    return null;
  },
  [Symbol.iterator]() {
    return iterable;
  },
};

function* generator() {
  yield* iterable;
}

// GetMethod returns undefined, so there shouldn't be an attempt to call.
var iterator = generator();
print(iterator.next().value);
iterator.return(123);
// CHECK-NEXT: 1
// CHECK-NEXT: get return
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -354,3 +354,18 @@
 iterator.return(123);
 // CHECK-NEXT: 1
 // CHECK-NEXT: get return
+
+// Make sure using SaveGeneratorLong works.
+function* saveGeneratorLong() {
+    yield* [1];
+    // Waste some registers, to change SaveGenerator to SaveGeneratorLong.
+    [].push(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
+    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
+    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
+    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
+    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
+    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
+    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
+}
+print(saveGeneratorLong().next().value);
+// CHECK-NEXT: 1
```
