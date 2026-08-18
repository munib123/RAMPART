# CrossVul Fix Pair: Always-Incorrect Control Flow Implementation in cpp
**Pair ID:** 4258_2
**Vulnerability Class:** Always-Incorrect Control Flow Implementation
**CWE:** CWE-670
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4258_2`)

## Vulnerability Information & PoC

## Description
Always-Incorrect Control Flow Implementation - This weakness captures cases in which a particular code segment is always incorrect with respect to the algorithm that it is implementing.

## Vulnerable Code
```cpp
Lines 984-1024 of the vulnerable file.

  ip = runtime->getCurrentIP();

#define CAPTURE_IP_ASSIGN(dst, expr) CAPTURE_IP_ASSIGN_NO_INVALIDATE(dst, expr)

#else // !NDEBUG

#define CAPTURE_IP(expr)        \
  runtime->setCurrentIP(ip);    \
  (void)expr;                   \
  ip = runtime->getCurrentIP(); \
  runtime->invalidateCurrentIP();

#define CAPTURE_IP_ASSIGN(dst, expr) \
  runtime->setCurrentIP(ip);         \
  dst = expr;                        \
  ip = runtime->getCurrentIP();      \
  runtime->invalidateCurrentIP();

#endif // NDEBUG

  LLVM_DEBUG(dbgs() << "interpretFunction() called\n");

  ScopedNativeDepthTracker depthTracker{runtime};
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime->raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }

  if (!SingleStep) {
    if (auto jitPtr = runtime->jitContext_.compile(runtime, curCodeBlock)) {
      return (*jitPtr)(runtime);
    }
  }

  GCScope gcScope(runtime);
  // Avoid allocating a handle dynamically by reusing this one.
  MutableHandle<> tmpHandle(runtime);
  CallResult<HermesValue> res{ExecutionStatus::EXCEPTION};
  CallResult<PseudoHandle<>> resPH{ExecutionStatus::EXCEPTION};
  CallResult<Handle<Arguments>> resArgs{ExecutionStatus::EXCEPTION};
  CallResult<bool> boolRes{ExecutionStatus::EXCEPTION};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1000,6 +1000,16 @@
   runtime->invalidateCurrentIP();
 
 #endif // NDEBUG
+
+/// \def DONT_CAPTURE_IP(expr)
+/// \param expr A call expression to a function external to the interpreter. The
+///   expression should not make any allocations and the IP should be set
+///   immediately following this macro.
+#define DONT_CAPTURE_IP(expr)      \
+  do {                             \
+    NoAllocScope noAlloc(runtime); \
+    (void)expr;                    \
+  } while (false)
 
   LLVM_DEBUG(dbgs() << "interpretFunction() called\n");
 
@@ -1798,24 +1808,17 @@
       }
 
       CASE(SaveGenerator) {
-        nextIP = IPADD(ip->iSaveGenerator.op1);
-        goto doSaveGen;
+        DONT_CAPTURE_IP(
+            saveGenerator(runtime, frameRegs, IPADD(ip->iSaveGenerator.op1)));
+        ip = NEXTINST(SaveGenerator);
+        DISPATCH;
       }
       CASE(SaveGeneratorLong) {
-        nextIP = IPADD(ip->iSaveGeneratorLong.op1);
-        goto doSaveGen;
-      }
-
-    doSaveGen : {
-      auto *innerFn = vmcast<GeneratorInnerFunction>(
-          runtime->getCurrentFrame().getCalleeClosure());
-
-      innerFn->saveStack(runtime);
-      innerFn->setNextIP(nextIP);
-      innerFn->setState(GeneratorInnerFunction::State::SuspendedYield);
-      ip = NEXTINST(SaveGenerator);
-      DISPATCH;
-    }
+        DONT_CAPTURE_IP(saveGenerator(
+            runtime, frameRegs, IPADD(ip->iSaveGeneratorLong.op1)));
+        ip = NEXTINST(SaveGeneratorLong);
+        DISPATCH;
+      }
 
       CASE(StartGenerator) {
         auto *innerFn = vmcast<GeneratorInnerFunction>(
```
