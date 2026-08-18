# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4271_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4271_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 766-806 of the vulnerable file.


l_noret luaG_runerror (lua_State *L, const char *fmt, ...) {
  CallInfo *ci = L->ci;
  const char *msg;
  va_list argp;
  luaC_checkGC(L);  /* error message uses memory */
  va_start(argp, fmt);
  msg = luaO_pushvfstring(L, fmt, argp);  /* format message */
  va_end(argp);
  if (isLua(ci))  /* if Lua function, add source:line information */
    luaG_addinfo(L, msg, ci_func(ci)->p->source, getcurrentline(ci));
  luaG_errormsg(L);
}


/*
** Check whether new instruction 'newpc' is in a different line from
** previous instruction 'oldpc'.
*/
static int changedline (const Proto *p, int oldpc, int newpc) {
  while (oldpc++ < newpc) {
    if (p->lineinfo[oldpc] != 0)
      return (luaG_getfuncline(p, oldpc - 1) != luaG_getfuncline(p, newpc));
  }
  return 0;  /* no line changes in the way */
}


/*
** Traces the execution of a Lua function. Called before the execution
** of each opcode, when debug is on. 'L->oldpc' stores the last
** instruction traced, to detect line changes. When entering a new
** function, 'npci' will be zero and will test as a new line without
** the need for 'oldpc'; so, 'oldpc' does not need to be initialized
** before. Some exceptional conditions may return to a function without
** updating 'oldpc'. In that case, 'oldpc' may be invalid; if so, it is
** reset to zero.  (A wrong but valid 'oldpc' at most causes an extra
** call to a line hook.)
*/
int luaG_traceexec (lua_State *L, const Instruction *pc) {
  CallInfo *ci = L->ci;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -783,11 +783,13 @@
 ** previous instruction 'oldpc'.
 */
 static int changedline (const Proto *p, int oldpc, int newpc) {
+  if (p->lineinfo == NULL)  /* no debug information? */
+    return 0;
   while (oldpc++ < newpc) {
     if (p->lineinfo[oldpc] != 0)
       return (luaG_getfuncline(p, oldpc - 1) != luaG_getfuncline(p, newpc));
   }
-  return 0;  /* no line changes in the way */
+  return 0;  /* no line changes between positions */
 }
 
 
```
