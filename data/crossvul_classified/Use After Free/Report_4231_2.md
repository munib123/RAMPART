# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4231_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4231_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 223-263 of the vulnerable file.

  if (isfloat) {
    setfltvalue(&aux, cast_num(v2));
  }
  else
    setivalue(&aux, v2);
  if (flip) {  /* arguments were exchanged? */
    p2 = p1; p1 = &aux;  /* correct them */
  }
  else
    p2 = &aux;
  return luaT_callorderTM(L, p1, p2, event);
}


void luaT_adjustvarargs (lua_State *L, int nfixparams, CallInfo *ci,
                         const Proto *p) {
  int i;
  int actual = cast_int(L->top - ci->func) - 1;  /* number of arguments */
  int nextra = actual - nfixparams;  /* number of extra arguments */
  ci->u.l.nextraargs = nextra;
  checkstackGC(L, p->maxstacksize + 1);
  /* copy function to the top of the stack */
  setobjs2s(L, L->top++, ci->func);
  /* move fixed parameters to the top of the stack */
  for (i = 1; i <= nfixparams; i++) {
    setobjs2s(L, L->top++, ci->func + i);
    setnilvalue(s2v(ci->func + i));  /* erase original parameter (for GC) */
  }
  ci->func += actual + 1;
  ci->top += actual + 1;
  lua_assert(L->top <= ci->top && ci->top <= L->stack_last);
}


void luaT_getvarargs (lua_State *L, CallInfo *ci, StkId where, int wanted) {
  int i;
  int nextra = ci->u.l.nextraargs;
  if (wanted < 0) {
    wanted = nextra;  /* get all extra arguments available */
    checkstackp(L, nextra, where);  /* ensure stack space */
    L->top = where + nextra;  /* next instruction will need top */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -240,7 +240,7 @@
   int actual = cast_int(L->top - ci->func) - 1;  /* number of arguments */
   int nextra = actual - nfixparams;  /* number of extra arguments */
   ci->u.l.nextraargs = nextra;
-  checkstackGC(L, p->maxstacksize + 1);
+  luaD_checkstack(L, p->maxstacksize + 1);
   /* copy function to the top of the stack */
   setobjs2s(L, L->top++, ci->func);
   /* move fixed parameters to the top of the stack */
@@ -259,7 +259,7 @@
   int nextra = ci->u.l.nextraargs;
   if (wanted < 0) {
     wanted = nextra;  /* get all extra arguments available */
-    checkstackp(L, nextra, where);  /* ensure stack space */
+    checkstackGCp(L, nextra, where);  /* ensure stack space */
     L->top = where + nextra;  /* next instruction will need top */
   }
   for (i = 0; i < wanted && i < nextra; i++)
```
