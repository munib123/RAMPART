# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 163_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `163_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 103-143 of the vulnerable file.

  if (jsvIsNewChild(dst)) {
    // Get what it should have been a child of
    JsVar *parent = jsvLock(jsvGetNextSibling(dst));
    if (!jsvIsString(parent)) {
      // if we can't find a char in a string we still return a NewChild,
      // but we can't add character back in
      if (!jsvHasChildren(parent)) {
        jsExceptionHere(JSET_ERROR, "Field or method \"%s\" does not already exist, and can't create it on %t", dst, parent);
      } else {
        // Remove the 'new child' flagging
        jsvUnRef(parent);
        jsvSetNextSibling(dst, 0);
        jsvUnRef(parent);
        jsvSetPrevSibling(dst, 0);
        // Add to the parent
        jsvAddName(parent, dst);
      }
    }
    jsvUnLock(parent);
  }
}

bool jspeiAddScope(JsVar *scope) {
  if (execInfo.scopeCount >= JSPARSE_MAX_SCOPES) {
    jsExceptionHere(JSET_ERROR, "Maximum number of scopes exceeded");
    jspSetError(false);
    return false;
  }
  execInfo.scopes[execInfo.scopeCount++] = jsvLockAgain(scope);
  return true;
}

void jspeiRemoveScope() {
  if (execInfo.scopeCount <= 0) {
    jsExceptionHere(JSET_INTERNALERROR, "Too many scopes removed");
    jspSetError(false);
    return;
  }
  jsvUnLock(execInfo.scopes[--execInfo.scopeCount]);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,6 +120,16 @@
     }
     jsvUnLock(parent);
   }
+}
+
+void jspReplaceWithOrAddToRoot(JsVar *dst, JsVar *src) {
+  /* If we're assigning to this and we don't have a parent,
+   * add it to the symbol table root */
+  if (!jsvGetRefs(dst) && jsvIsName(dst)) {
+    if (!jsvIsArrayBufferName(dst) && !jsvIsNewChild(dst))
+      jsvAddName(execInfo.root, dst);
+  }
+  jspReplaceWith(dst, src);
 }
 
 bool jspeiAddScope(JsVar *scope) {
@@ -1971,13 +1981,7 @@
 
     if (JSP_SHOULD_EXECUTE && lhs) {
       if (op=='=') {
-        /* If we're assigning to this and we don't have a parent,
-         * add it to the symbol table root */
-        if (!jsvGetRefs(lhs) && jsvIsName(lhs)) {
-          if (!jsvIsArrayBufferName(lhs) && !jsvIsNewChild(lhs))
-            jsvAddName(execInfo.root, lhs);
-        }
-        jspReplaceWith(lhs, rhs);
+        jspReplaceWithOrAddToRoot(lhs, rhs);
       } else {
         if (op==LEX_PLUSEQUAL) op='+';
         else if (op==LEX_MINUSEQUAL) op='-';
@@ -2330,12 +2334,6 @@
       jsExceptionHere(JSET_ERROR, "FOR a IN b - 'a' must be a variable name, not %t", forStatement);
       return 0;
     }
-    bool addedIteratorToScope = false;
-    if (JSP_SHOULD_EXECUTE && !jsvGetRefs(forStatement)) {
-      // if the variable did not exist, add it to the scope
-      addedIteratorToScope = true;
-      jsvAddName(execInfo.root, forStatement);
-    }
     JSP_MATCH_WITH_CLEANUP_AND_RETURN(LEX_R_IN, jsvUnLock(forStatement), 0);
     JsVar *array = jsvSkipNameAndUnLock(jspeExpression());
     JSP_MATCH_WITH_CLEANUP_AND_RETURN(')', jsvUnLock2(forStatement, array), 0);
@@ -2371,7 +2369,7 @@
                 loopIndexVar;
             if (indexValue) { // could be out of memory
               assert(!jsvIsName(indexValue) && jsvGetRefs(indexValue)==0);
-              jsvSetValueOfName(forStatement, indexValue);
+              jspReplaceWithOrAddToRoot(forStatement, indexValue);
               if (indexValue!=loopIndexVar) jsvUnLock(indexValue);
 
               jsvIteratorNext(&it);
@@ -2410,9 +2408,6 @@
     jslCharPosFree(&forBodyStart);
     jslCharPosFree(&forBodyEnd);
 
-    if (addedIteratorToScope) {
-      jsvRemoveChild(execInfo.root, forStatement);
-    }
     jsvUnLock2(forStatement, array);
   } else { // ----------------------------------------------- NORMAL FOR LOOP
 #ifdef JSPARSE_MAX_LOOP_ITERATIONS
```
