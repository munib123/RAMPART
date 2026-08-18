# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 2487_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2487_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 576-597 of the vulnerable file.

    },
    {
        name: "[MSRC34994,35226] heap overflow in Array.prototype.reverse",
        body: function ()
        {
            var count = 0;
            arr = new Array(100);
            var desc = Object.getOwnPropertyDescriptor(Array.prototype, 1);
            Object.defineProperty(Array.prototype, 1, { get: function () {
                    count++;
                    if (count == 1) {
                        arr.push(null);
                    }
                }});

            arr.reverse();
            restorePropertyFromDescriptor(Array.prototype, 1, desc);
            assert.areEqual(101, arr.length);
        }
    },
];
testRunner.runTests(tests, { verbose: WScript.Arguments[0] != "summary" });
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -593,5 +593,32 @@
             assert.areEqual(101, arr.length);
         }
     },
+    {
+        name: "Heap overread when splice mutates the array when executing slice",
+        body: function ()
+        {
+            var getterCalled = false;
+            var a = [1, 2];
+            for (var i = 0; i < 100 * 1024; i++) {
+                a.push(i);
+            }
+            delete a[0]; // Make a missing item
+            var protoObj = [11];
+            Object.defineProperty(protoObj, '0', {
+                get : function () {
+                    getterCalled = true;
+                    Object.setPrototypeOf(a, Array.prototype);
+                    a.splice(0); // head seg is now length=0
+                    return 42;
+                },
+                configurable : true
+            });
+            Object.setPrototypeOf(a, protoObj);
+            var b = a.slice();
+            assert.isTrue(getterCalled);
+            assert.areEqual(0, a.length, "Getter will splice the array to zero length");
+            assert.areEqual(100 * 1024 + 2, b.length, "Validating that slice will return the full array even though splice is deleting the whole array");
+        }
+    },
 ];
 testRunner.runTests(tests, { verbose: WScript.Arguments[0] != "summary" });
```
