# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1629_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1629_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 478-518 of the vulnerable file.

}



/*
** Execute a protected parser.
*/
struct SParser {  /* data to `f_parser' */
  ZIO *z;
  Mbuffer buff;  /* buffer to be used by the scanner */
  const char *name;
};

static void f_parser (lua_State *L, void *ud) {
  int i;
  Proto *tf;
  Closure *cl;
  struct SParser *p = cast(struct SParser *, ud);
  int c = luaZ_lookahead(p->z);
  luaC_checkGC(L);
  tf = ((c == LUA_SIGNATURE[0]) ? luaU_undump : luaY_parser)(L, p->z,
                                                             &p->buff, p->name);
  cl = luaF_newLclosure(L, tf->nups, hvalue(gt(L)));
  cl->l.p = tf;
  for (i = 0; i < tf->nups; i++)  /* initialize eventual upvalues */
    cl->l.upvals[i] = luaF_newupval(L);
  setclvalue(L, L->top, cl);
  incr_top(L);
}


int luaD_protectedparser (lua_State *L, ZIO *z, const char *name) {
  struct SParser p;
  int status;
  p.z = z; p.name = name;
  luaZ_initbuffer(L, &p.buff);
  status = luaD_pcall(L, f_parser, &p, savestack(L, L->top), L->errfunc);
  luaZ_freebuffer(L, &p.buff);
  return status;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -495,7 +495,7 @@
   struct SParser *p = cast(struct SParser *, ud);
   int c = luaZ_lookahead(p->z);
   luaC_checkGC(L);
-  tf = ((c == LUA_SIGNATURE[0]) ? luaU_undump : luaY_parser)(L, p->z,
+  tf = (luaY_parser)(L, p->z,
                                                              &p->buff, p->name);
   cl = luaF_newLclosure(L, tf->nups, hvalue(gt(L)));
   cl->l.p = tf;
```
