# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in javascript
**Pair ID:** 2486_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2486_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```javascript
Lines 142-182 of the vulnerable file.

        assert.areEqual(10, f7()(), "Recursive call to the function from the body scope returns the right value");
        
        var f9 = function f10 (a = function ( ) { b; return f10(20); }, b) {
            eval("");
            if (a == 20) {
                return 10;
            }
            return a;
        }
        assert.areEqual(10, f9()(), "Recursive call to the function from the param scope returns the right value when eval is there in the body");
        
        var f11 = function f12 (a = function ( ) { b; }, b) {
            eval("");
            if (a == 20) {
                return 10;
            }
            var a = function () { return f12(20); };
            return a;
        }
        assert.areEqual(10, f11()(), "Recursive call to the function from the body scope returns the right value when eval is there in the body");
    } 
 }, 
 { 
    name: "Split parameter scope in member functions", 
    body: function () { 
       var o1 = { 
           f(a = 10, b = function () { return a; }) { 
               assert.areEqual(10, a, "Initial value of parameter in the body scope of the method should be the same as the one in param scope"); 
               var a = 20; 
               assert.areEqual(20, a, "New assignment in the body scope of the method updates the variable's value in body scope"); 
                return b; 
            } 
        } 
        assert.areEqual(o1.f()(), 10, "Function defined in the param scope of the object method captures the formals from the param scope not body scope"); 
         
        var o2 = { 
            f1(a = 10, b = function () { return { f2 () { return a; } } }) { 
                var a = 20; 
                c = function () { return { f2 () { return a; } } }; 
                return [b, c]; 
            } 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -159,6 +159,22 @@
             return a;
         }
         assert.areEqual(10, f11()(), "Recursive call to the function from the body scope returns the right value when eval is there in the body");
+
+        function f13() {
+            var a = function jnvgfg(sfgnmj = function ccunlk() { jnvgfg(undefined, 1); }, b) {
+                if (b) {
+                    assert.areEqual(undefined, jnvgfg, "This refers to the instance in the body and the value of the function expression is not copied over");
+                }
+                var jnvgfg = 10;
+                if (!b) {
+                    sfgnmj();
+                    return 100;
+                }
+            };
+            assert.areEqual(100, a(), "After the recursion the right value is returned by the split scoped function");
+        };
+        f13();
+
     } 
  }, 
  { 
```
