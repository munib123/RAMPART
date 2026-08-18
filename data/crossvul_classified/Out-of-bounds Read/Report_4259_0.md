# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4259_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4259_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 1682-1722 of the vulnerable file.

      if (LLVM_UNLIKELY(desc.flags.accessor || !desc.flags.writable)) {
        return false;
      }

      if (LLVM_LIKELY(
              !desc.flags.internalSetter && !receiverHandle->isHostObject() &&
              !receiverHandle->isProxyObject())) {
        if (LLVM_UNLIKELY(
                setComputedSlotValue(
                    receiverHandle, runtime, desc, valueHandle) ==
                ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        return true;
      }
    }

    if (LLVM_UNLIKELY(
            desc.flags.internalSetter || receiverHandle->isHostObject() ||
            receiverHandle->isProxyObject())) {
      SymbolID id{};
      LAZY_TO_IDENTIFIER(runtime, nameValPrimitiveHandle, id);
      if (desc.flags.internalSetter) {
        return internalSetter(
            receiverHandle,
            runtime,
            id,
            desc.castToNamedPropertyDescriptorRef(),
            valueHandle,
            opFlags);
      } else if (receiverHandle->isHostObject()) {
        return vmcast<HostObject>(receiverHandle.get())->set(id, *valueHandle);
      }
      assert(
          receiverHandle->isProxyObject() && "descriptor flags are impossible");
      if (*descDefinedRes) {
        dpf.setValue = 1;
      } else {
        dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
      }
      return JSProxy::defineOwnProperty(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1699,6 +1699,24 @@
     if (LLVM_UNLIKELY(
             desc.flags.internalSetter || receiverHandle->isHostObject() ||
             receiverHandle->isProxyObject())) {
+      // If putComputed is called on a proxy whose target's prototype
+      // is an array with a propname of 'length', then internalSetter
+      // will be true, and the receiver will be a proxy.  In that case,
+      // proxy wins.
+      if (receiverHandle->isProxyObject()) {
+        if (*descDefinedRes) {
+          dpf.setValue = 1;
+        } else {
+          dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
+        }
+        return JSProxy::defineOwnProperty(
+            receiverHandle,
+            runtime,
+            nameValPrimitiveHandle,
+            dpf,
+            valueHandle,
+            opFlags);
+      }
       SymbolID id{};
       LAZY_TO_IDENTIFIER(runtime, nameValPrimitiveHandle, id);
       if (desc.flags.internalSetter) {
@@ -1709,23 +1727,10 @@
             desc.castToNamedPropertyDescriptorRef(),
             valueHandle,
             opFlags);
-      } else if (receiverHandle->isHostObject()) {
-        return vmcast<HostObject>(receiverHandle.get())->set(id, *valueHandle);
       }
       assert(
-          receiverHandle->isProxyObject() && "descriptor flags are impossible");
-      if (*descDefinedRes) {
-        dpf.setValue = 1;
-      } else {
-        dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
-      }
-      return JSProxy::defineOwnProperty(
-          receiverHandle,
-          runtime,
-          nameValPrimitiveHandle,
-          dpf,
-          valueHandle,
-          opFlags);
+          receiverHandle->isHostObject() && "descriptor flags are impossible");
+      return vmcast<HostObject>(receiverHandle.get())->set(id, *valueHandle);
     }
   }
 
```
