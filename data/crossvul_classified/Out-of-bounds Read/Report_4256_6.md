# CrossVul Fix Pair: Out-of-bounds Read in javascript
**Pair ID:** 4256_6
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4256_6`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```javascript
Lines 30-70 of the vulnerable file.

//CHECK-NEXT:  %6 = SaveAndYieldInst 1 : number, %BB3
//CHECK-NEXT:%BB1:
//CHECK-NEXT:  %7 = ReturnInst %2
//CHECK-NEXT:%BB3:
//CHECK-NEXT:  %8 = ResumeGeneratorInst %5
//CHECK-NEXT:  %9 = LoadStackInst %5
//CHECK-NEXT:  %10 = CondBranchInst %9, %BB4, %BB5
//CHECK-NEXT:%BB5:
//CHECK-NEXT:  %11 = ReturnInst undefined : undefined
//CHECK-NEXT:%BB4:
//CHECK-NEXT:  %12 = ReturnInst %8
//CHECK-NEXT:function_end

function *useResult() {
  var x = yield 1;
}
//CHECK-LABEL:function useResult()
//CHECK-NEXT:frame = [x]
//CHECK-NEXT:%BB0:
//CHECK-NEXT:  %0 = StoreFrameInst undefined : undefined, [x]
//CHECK-NEXT:  %1 = CreateGeneratorInst %?anon_1_useResult()
//CHECK-NEXT:  %2 = ReturnInst %1 : object
//CHECK-NEXT:function_end

//CHECK-LABEL:function ?anon_1_useResult()
//CHECK-NEXT:frame = [x]
//CHECK-NEXT:%BB0:
//CHECK-NEXT:  %0 = StartGeneratorInst
//CHECK-NEXT:  %1 = AllocStackInst $?anon_0_isReturn_prologue
//CHECK-NEXT:  %2 = ResumeGeneratorInst %1
//CHECK-NEXT:  %3 = LoadStackInst %1
//CHECK-NEXT:  %4 = CondBranchInst %3, %BB1, %BB2
//CHECK-NEXT:%BB2:
//CHECK-NEXT:  %5 = StoreFrameInst undefined : undefined, [x]
//CHECK-NEXT:  %6 = AllocStackInst $?anon_1_isReturn
//CHECK-NEXT:  %7 = SaveAndYieldInst 1 : number, %BB3
//CHECK-NEXT:%BB1:
//CHECK-NEXT:  %8 = ReturnInst %2
//CHECK-NEXT:%BB3:
//CHECK-NEXT:  %9 = ResumeGeneratorInst %6
//CHECK-NEXT:  %10 = LoadStackInst %6
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,11 +47,11 @@
 //CHECK-NEXT:frame = [x]
 //CHECK-NEXT:%BB0:
 //CHECK-NEXT:  %0 = StoreFrameInst undefined : undefined, [x]
-//CHECK-NEXT:  %1 = CreateGeneratorInst %?anon_1_useResult()
+//CHECK-NEXT:  %1 = CreateGeneratorInst %?anon_0_useResult()
 //CHECK-NEXT:  %2 = ReturnInst %1 : object
 //CHECK-NEXT:function_end
 
-//CHECK-LABEL:function ?anon_1_useResult()
+//CHECK-LABEL:function ?anon_0_useResult()
 //CHECK-NEXT:frame = [x]
 //CHECK-NEXT:%BB0:
 //CHECK-NEXT:  %0 = StartGeneratorInst
@@ -86,11 +86,11 @@
 //CHECK-NEXT:frame = [i]
 //CHECK-NEXT:%BB0:
 //CHECK-NEXT:  %0 = StoreFrameInst undefined : undefined, [i]
-//CHECK-NEXT:  %1 = CreateGeneratorInst %?anon_2_loop()
+//CHECK-NEXT:  %1 = CreateGeneratorInst %?anon_0_loop()
 //CHECK-NEXT:  %2 = ReturnInst %1 : object
 //CHECK-NEXT:function_end
 
-//CHECK-LABEL:function ?anon_2_loop(x)
+//CHECK-LABEL:function ?anon_0_loop(x)
 //CHECK-NEXT:frame = [i, x]
 //CHECK-NEXT:%BB0:
 //CHECK-NEXT:  %0 = StartGeneratorInst
@@ -139,11 +139,11 @@
 //CHECK-LABEL:function simple2()
 //CHECK-NEXT:frame = []
 //CHECK-NEXT:%BB0:
-//CHECK-NEXT:  %0 = CreateGeneratorInst %?anon_4_simple2()
+//CHECK-NEXT:  %0 = CreateGeneratorInst %?anon_0_simple2()
 //CHECK-NEXT:  %1 = ReturnInst %0 : object
 //CHECK-NEXT:function_end
 
-//CHECK-LABEL:function ?anon_4_simple2()
+//CHECK-LABEL:function ?anon_0_simple2()
 //CHECK-NEXT:frame = []
 //CHECK-NEXT:%BB0:
 //CHECK-NEXT:  %0 = StartGeneratorInst
@@ -172,11 +172,11 @@
 //CHECK-LABEL:function yieldStar()
 //CHECK-NEXT:frame = []
 //CHECK-NEXT:%BB0:
-//CHECK-NEXT:  %0 = CreateGeneratorInst %?anon_5_yieldStar()
+//CHECK-NEXT:  %0 = CreateGeneratorInst %?anon_0_yieldStar()
 //CHECK-NEXT:  %1 = ReturnInst %0 : object
 //CHECK-NEXT:function_end
 
-//CHECK-LABEL:function ?anon_5_yieldStar()
+//CHECK-LABEL:function ?anon_0_yieldStar()
 //CHECK-NEXT:frame = []
 //CHECK-NEXT:%BB0:
 //CHECK-NEXT:  %0 = StartGeneratorInst
@@ -281,13 +281,13 @@
 //CHECK-LABEL:function destr()
 //CHECK-NEXT:frame = []
 //CHECK-NEXT:%BB0:
-//CHECK-NEXT:  %0 = CreateGeneratorInst %?anon_6_destr()
+//CHECK-NEXT:  %0 = CreateGeneratorInst %?anon_0_destr()
 //CHECK-NEXT:  %1 = LoadPropertyInst %0 : object, "next" : string
 //CHECK-NEXT:  %2 = CallInst %1, %0 : object
 //CHECK-NEXT:  %3 = ReturnInst %0 : object
 //CHECK-NEXT:function_end
 
-//CHECK-LABEL:function ?anon_6_destr(?anon_2_param)
+//CHECK-LABEL:function ?anon_0_destr(?anon_2_param)
 //CHECK-NEXT:frame = [x]
 //CHECK-NEXT:%BB0:
 //CHECK-NEXT:  %0 = StartGeneratorInst
@@ -355,13 +355,13 @@
 //CHECK-LABEL:function initializer()
 //CHECK-NEXT:frame = []
 //CHECK-NEXT:%BB0:
-//CHECK-NEXT:  %0 = CreateGeneratorInst %?anon_7_initializer()
+//CHECK-NEXT:  %0 = CreateGeneratorInst %?anon_0_initializer()
 //CHECK-NEXT:  %1 = LoadPropertyInst %0 : object, "next" : string
 //CHECK-NEXT:  %2 = CallInst %1, %0 : object
 //CHECK-NEXT:  %3 = ReturnInst %0 : object
 //CHECK-NEXT:function_end
 
-//CHECK-LABEL:function ?anon_7_initializer(x)
+//CHECK-LABEL:function ?anon_0_initializer(x)
 //CHECK-NEXT:frame = [x]
 //CHECK-NEXT:%BB0:
 //CHECK-NEXT:  %0 = StartGeneratorInst
```
