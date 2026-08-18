# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4270_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4270_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 498-540 of the vulnerable file.

      ci->top = func + 1 + fsize;
      ci->func = func;
      L->ci = ci;
      for (; narg < nfixparams; narg++)
        setnilvalue(s2v(L->top++));  /* complete missing arguments */
      lua_assert(ci->top <= L->stack_last);
      luaV_execute(L, ci);  /* run the function */
      break;
    }
    default: {  /* not a function */
      checkstackGCp(L, 1, func);  /* space for metamethod */
      luaD_tryfuncTM(L, func);  /* try to get '__call' metamethod */
      goto retry;  /* try again with metamethod */
    }
  }
}


/*
** Similar to 'luaD_call', but does not allow yields during the call.
** If there is a stack overflow, freeing all CI structures will
** force the subsequent call to invoke 'luaE_extendCI', which then
** will raise any errors.
*/
void luaD_callnoyield (lua_State *L, StkId func, int nResults) {
  incXCcalls(L);
  if (getCcalls(L) <= CSTACKERR)  /* possible stack overflow? */
    luaE_freeCI(L);
  luaD_call(L, func, nResults);
  decXCcalls(L);
}


/*
** Completes the execution of an interrupted C function, calling its
** continuation function.
*/
static void finishCcall (lua_State *L, int status) {
  CallInfo *ci = L->ci;
  int n;
  /* must have a continuation and must be able to call it */
  lua_assert(ci->u.c.k != NULL && yieldable(L));
  /* error status can only happen in a protected call */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -515,14 +515,13 @@
 
 /*
 ** Similar to 'luaD_call', but does not allow yields during the call.
-** If there is a stack overflow, freeing all CI structures will
-** force the subsequent call to invoke 'luaE_extendCI', which then
-** will raise any errors.
 */
 void luaD_callnoyield (lua_State *L, StkId func, int nResults) {
   incXCcalls(L);
-  if (getCcalls(L) <= CSTACKERR)  /* possible stack overflow? */
-    luaE_freeCI(L);
+  if (getCcalls(L) <= CSTACKERR) {  /* possible C stack overflow? */
+    luaE_exitCcall(L);  /* to compensate decrement in next call */
+    luaE_enterCcall(L);  /* check properly */
+  }
   luaD_call(L, func, nResults);
   decXCcalls(L);
 }
```
