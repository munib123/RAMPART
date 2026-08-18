# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4231_3
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4231_3`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1617-1657 of the vulnerable file.

      vmcase(OP_TAILCALL) {
        int b = GETARG_B(i);  /* number of arguments + 1 (function) */
        int nparams1 = GETARG_C(i);
        /* delat is virtual 'func' - real 'func' (vararg functions) */
        int delta = (nparams1) ? ci->u.l.nextraargs + nparams1 : 0;
        if (b != 0)
          L->top = ra + b;
        else  /* previous instruction set top */
          b = cast_int(L->top - ra);
        savepc(ci);  /* some calls here can raise errors */
        if (TESTARG_k(i)) {
          /* close upvalues from current call; the compiler ensures
             that there are no to-be-closed variables here, so this
             call cannot change the stack */
          luaF_close(L, base, NOCLOSINGMETH);
          lua_assert(base == ci->func + 1);
        }
        while (!ttisfunction(s2v(ra))) {  /* not a function? */
          luaD_tryfuncTM(L, ra);  /* try '__call' metamethod */
          b++;  /* there is now one extra argument */
          checkstackp(L, 1, ra);
        }
        if (!ttisLclosure(s2v(ra))) {  /* C function? */
          luaD_call(L, ra, LUA_MULTRET);  /* call it */
          updatetrap(ci);
          updatestack(ci);  /* stack may have been relocated */
          ci->func -= delta;
          luaD_poscall(L, ci, cast_int(L->top - ra));
          return;
        }
        ci->func -= delta;
        luaD_pretailcall(L, ci, ra, b);  /* prepare call frame */
        goto tailcall;
      }
      vmcase(OP_RETURN) {
        int n = GETARG_B(i) - 1;  /* number of results */
        int nparams1 = GETARG_C(i);
        if (n < 0)  /* not fixed? */
          n = cast_int(L->top - ra);  /* get what is available */
        savepc(ci);
        if (TESTARG_k(i)) {  /* may there be open upvalues? */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1634,7 +1634,7 @@
         while (!ttisfunction(s2v(ra))) {  /* not a function? */
           luaD_tryfuncTM(L, ra);  /* try '__call' metamethod */
           b++;  /* there is now one extra argument */
-          checkstackp(L, 1, ra);
+          checkstackGCp(L, 1, ra);
         }
         if (!ttisLclosure(s2v(ra))) {  /* C function? */
           luaD_call(L, ra, LUA_MULTRET);  /* call it */
```
