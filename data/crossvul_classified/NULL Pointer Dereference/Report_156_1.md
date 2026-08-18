# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 156_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `156_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 3297-3337 of the vulnerable file.

    jsiConsolePrint("...\n");
    return;
  }

  if (jsvIsName(var)) jsiConsolePrint("Name ");

  char endBracket = ' ';
  if (jsvIsObject(var)) { jsiConsolePrint("Object { "); endBracket = '}'; }
  else if (jsvIsArray(var)) { jsiConsolePrintf("Array(%d) [ ", var->varData.integer); endBracket = ']'; }
  else if (jsvIsNativeFunction(var)) { jsiConsolePrintf("NativeFunction 0x%x (%d) { ", var->varData.native.ptr, var->varData.native.argTypes); endBracket = '}'; }
  else if (jsvIsFunction(var)) {
    jsiConsolePrint("Function { ");
    if (jsvIsFunctionReturn(var)) jsiConsolePrint("return ");
    endBracket = '}';
  } else if (jsvIsPin(var)) jsiConsolePrintf("Pin %d", jsvGetInteger(var));
  else if (jsvIsInt(var)) jsiConsolePrintf("Integer %d", jsvGetInteger(var));
  else if (jsvIsBoolean(var)) jsiConsolePrintf("Bool %s", jsvGetBool(var)?"true":"false");
  else if (jsvIsFloat(var)) jsiConsolePrintf("Double %f", jsvGetFloat(var));
  else if (jsvIsFunctionParameter(var)) jsiConsolePrintf("Param %q ", var);
  else if (jsvIsArrayBufferName(var)) jsiConsolePrintf("ArrayBufferName[%d] ", jsvGetInteger(var));
  else if (jsvIsArrayBuffer(var)) jsiConsolePrintf("%s ", jswGetBasicObjectName(var)); // way to get nice name
  else if (jsvIsString(var)) {
    size_t blocks = 1;
    if (jsvGetLastChild(var)) {
      JsVar *v = jsvLock(jsvGetLastChild(var));
      blocks += jsvCountJsVarsUsed(v);
      jsvUnLock(v);
    }
    if (jsvIsFlatString(var)) {
      blocks += jsvGetFlatStringBlocks(var);
    }
    jsiConsolePrintf("%sString [%d blocks] %q", jsvIsFlatString(var)?"Flat":(jsvIsNativeString(var)?"Native":""), blocks, var);
  } else {
    jsiConsolePrintf("Unknown %d", var->flags & (JsVarFlags)~(JSV_LOCK_MASK));
  }

  // print a value if it was stored in here as well...
  if (jsvIsNameInt(var)) {
    jsiConsolePrintf("= int %d\n", (int)jsvGetFirstChildSigned(var));
    return;
  } else if (jsvIsNameIntBool(var)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3314,7 +3314,7 @@
   else if (jsvIsFloat(var)) jsiConsolePrintf("Double %f", jsvGetFloat(var));
   else if (jsvIsFunctionParameter(var)) jsiConsolePrintf("Param %q ", var);
   else if (jsvIsArrayBufferName(var)) jsiConsolePrintf("ArrayBufferName[%d] ", jsvGetInteger(var));
-  else if (jsvIsArrayBuffer(var)) jsiConsolePrintf("%s ", jswGetBasicObjectName(var)); // way to get nice name
+  else if (jsvIsArrayBuffer(var)) jsiConsolePrintf("%s ", jswGetBasicObjectName(var)?jswGetBasicObjectName(var):"unknown ArrayBuffer"); // way to get nice name
   else if (jsvIsString(var)) {
     size_t blocks = 1;
     if (jsvGetLastChild(var)) {
```
