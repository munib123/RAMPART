# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4230_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4230_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 228-268 of the vulnerable file.

      else return 0;
    }
  }  /* else no errors */
  return luaD_reallocstack(L, newsize, raiseerror);
}


static int stackinuse (lua_State *L) {
  CallInfo *ci;
  StkId lim = L->top;
  for (ci = L->ci; ci != NULL; ci = ci->previous) {
    if (lim < ci->top) lim = ci->top;
  }
  lua_assert(lim <= L->stack_last);
  return cast_int(lim - L->stack) + 1;  /* part of stack in use */
}


void luaD_shrinkstack (lua_State *L) {
  int inuse = stackinuse(L);
  int goodsize = inuse + (inuse / 8) + 2*EXTRA_STACK;
  if (goodsize > LUAI_MAXSTACK)
    goodsize = LUAI_MAXSTACK;  /* respect stack limit */
  /* if thread is currently not handling a stack overflow and its
     good size is smaller than current size, shrink its stack */
  if (inuse <= (LUAI_MAXSTACK - EXTRA_STACK) &&
      goodsize < L->stacksize)
    luaD_reallocstack(L, goodsize, 0);  /* ok if that fails */
  else  /* don't change stack */
    condmovestack(L,{},{});  /* (change only for debugging) */
  luaE_shrinkCI(L);  /* shrink CI list */
}


void luaD_inctop (lua_State *L) {
  luaD_checkstack(L, 1);
  L->top++;
}

/* }================================================================== */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -245,13 +245,12 @@
 
 void luaD_shrinkstack (lua_State *L) {
   int inuse = stackinuse(L);
-  int goodsize = inuse + (inuse / 8) + 2*EXTRA_STACK;
+  int goodsize = inuse + BASIC_STACK_SIZE;
   if (goodsize > LUAI_MAXSTACK)
     goodsize = LUAI_MAXSTACK;  /* respect stack limit */
   /* if thread is currently not handling a stack overflow and its
      good size is smaller than current size, shrink its stack */
-  if (inuse <= (LUAI_MAXSTACK - EXTRA_STACK) &&
-      goodsize < L->stacksize)
+  if (inuse <= (LUAI_MAXSTACK - EXTRA_STACK) && goodsize < L->stacksize)
     luaD_reallocstack(L, goodsize, 0);  /* ok if that fails */
   else  /* don't change stack */
     condmovestack(L,{},{});  /* (change only for debugging) */
```
