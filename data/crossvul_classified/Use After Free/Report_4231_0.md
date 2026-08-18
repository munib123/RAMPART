# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4231_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4231_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 448-489 of the vulnerable file.

}


/*
** Call a function (C or Lua). The function to be called is at *func.
** The arguments are on the stack, right after the function.
** When returns, all the results are on the stack, starting at the original
** function position.
*/
void luaD_call (lua_State *L, StkId func, int nresults) {
  lua_CFunction f;
 retry:
  switch (ttypetag(s2v(func))) {
    case LUA_VCCL:  /* C closure */
      f = clCvalue(s2v(func))->f;
      goto Cfunc;
    case LUA_VLCF:  /* light C function */
      f = fvalue(s2v(func));
     Cfunc: {
      int n;  /* number of returns */
      CallInfo *ci = next_ci(L);
      checkstackp(L, LUA_MINSTACK, func);  /* ensure minimum stack size */
      ci->nresults = nresults;
      ci->callstatus = CIST_C;
      ci->top = L->top + LUA_MINSTACK;
      ci->func = func;
      L->ci = ci;
      lua_assert(ci->top <= L->stack_last);
      if (L->hookmask & LUA_MASKCALL) {
        int narg = cast_int(L->top - func) - 1;
        luaD_hook(L, LUA_HOOKCALL, -1, 1, narg);
      }
      lua_unlock(L);
      n = (*f)(L);  /* do the actual call */
      lua_lock(L);
      api_checknelems(L, n);
      luaD_poscall(L, ci, n);
      break;
    }
    case LUA_VLCL: {  /* Lua function */
      CallInfo *ci = next_ci(L);
      Proto *p = clLvalue(s2v(func))->p;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -465,13 +465,13 @@
       f = fvalue(s2v(func));
      Cfunc: {
       int n;  /* number of returns */
-      CallInfo *ci = next_ci(L);
-      checkstackp(L, LUA_MINSTACK, func);  /* ensure minimum stack size */
+      CallInfo *ci;
+      checkstackGCp(L, LUA_MINSTACK, func);  /* ensure minimum stack size */
+      L->ci = ci = next_ci(L);
       ci->nresults = nresults;
       ci->callstatus = CIST_C;
       ci->top = L->top + LUA_MINSTACK;
       ci->func = func;
-      L->ci = ci;
       lua_assert(ci->top <= L->stack_last);
       if (L->hookmask & LUA_MASKCALL) {
         int narg = cast_int(L->top - func) - 1;
@@ -485,12 +485,13 @@
       break;
     }
     case LUA_VLCL: {  /* Lua function */
-      CallInfo *ci = next_ci(L);
+      CallInfo *ci;
       Proto *p = clLvalue(s2v(func))->p;
       int narg = cast_int(L->top - func) - 1;  /* number of real arguments */
       int nfixparams = p->numparams;
       int fsize = p->maxstacksize;  /* frame size */
-      checkstackp(L, fsize, func);
+      checkstackGCp(L, fsize, func);
+      L->ci = ci = next_ci(L);
       ci->nresults = nresults;
       ci->u.l.savedpc = p->code;  /* starting point */
       ci->callstatus = 0;
@@ -504,7 +505,7 @@
       break;
     }
     default: {  /* not a function */
-      checkstackp(L, 1, func);  /* space for metamethod */
+      checkstackGCp(L, 1, func);  /* space for metamethod */
       luaD_tryfuncTM(L, func);  /* try to get '__call' metamethod */
       goto retry;  /* try again with metamethod */
     }
```
