# CrossVul Fix Pair: Access of Resource Using Incompatible Type ('Type Confusion') in cpp
**Pair ID:** 4255_1
**Vulnerability Class:** Access of Resource Using Incompatible Type ('Type Confusion')
**CWE:** CWE-843
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4255_1`)

## Vulnerability Information & PoC

## Description
Access of Resource Using Incompatible Type ('Type Confusion') - When the product accesses the resource using an incompatible type, this could trigger logical errors because the resource does not have expected properties.

## Vulnerable Code
```cpp
Lines 1156-1196 of the vulnerable file.

    return createPseudoHandle(HermesValue::encodeUndefinedValue());

  if (LLVM_LIKELY(
          !desc.flags.accessor && !desc.flags.hostObject &&
          !desc.flags.proxyObject))
    return createPseudoHandle(
        getComputedSlotValue(propObj.get(), runtime, desc));

  if (desc.flags.accessor) {
    auto *accessor = vmcast<PropertyAccessor>(
        getComputedSlotValue(propObj.get(), runtime, desc));
    if (!accessor->getter)
      return createPseudoHandle(HermesValue::encodeUndefinedValue());

    // Execute the accessor on this object.
    return accessor->getter.get(runtime)->executeCall0(
        runtime->makeHandle(accessor->getter), runtime, receiver);
  } else if (desc.flags.hostObject) {
    SymbolID id{};
    LAZY_TO_IDENTIFIER(runtime, nameValPrimitiveHandle, id);
    auto propRes = vmcast<HostObject>(selfHandle.get())->get(id);
    if (propRes == ExecutionStatus::EXCEPTION)
      return ExecutionStatus::EXCEPTION;
    return createPseudoHandle(*propRes);
  } else {
    assert(desc.flags.proxyObject && "descriptor flags are impossible");
    CallResult<Handle<>> key = toPropertyKey(runtime, nameValPrimitiveHandle);
    if (key == ExecutionStatus::EXCEPTION)
      return ExecutionStatus::EXCEPTION;
    return JSProxy::getComputed(propObj, runtime, *key, receiver);
  }
}

CallResult<bool> JSObject::hasNamed(
    Handle<JSObject> selfHandle,
    Runtime *runtime,
    SymbolID name) {
  NamedPropertyDescriptor desc;
  JSObject *propObj = getNamedDescriptor(selfHandle, runtime, name, desc);
  if (propObj == nullptr) {
    return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1173,7 +1173,7 @@
   } else if (desc.flags.hostObject) {
     SymbolID id{};
     LAZY_TO_IDENTIFIER(runtime, nameValPrimitiveHandle, id);
-    auto propRes = vmcast<HostObject>(selfHandle.get())->get(id);
+    auto propRes = vmcast<HostObject>(propObj.get())->get(id);
     if (propRes == ExecutionStatus::EXCEPTION)
       return ExecutionStatus::EXCEPTION;
     return createPseudoHandle(*propRes);
```
