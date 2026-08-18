# CrossVul Fix Pair: Integer Underflow (Wrap or Wraparound) in c
**Pair ID:** 4272_0
**Vulnerability Class:** Integer Underflow (Wrap or Wraparound)
**CWE:** CWE-191
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4272_0`)

## Vulnerability Information & PoC

## Description
Integer Underflow (Wrap or Wraparound) - This can happen in signed and unsigned cases.

## Vulnerable Code
```c
Lines 171-212 of the vulnerable file.

  if (level == 0 && ci != &L->base_ci) {  /* level found? */
    status = 1;
    ar->i_ci = ci;
  }
  else status = 0;  /* no such level */
  lua_unlock(L);
  return status;
}


static const char *upvalname (const Proto *p, int uv) {
  TString *s = check_exp(uv < p->sizeupvalues, p->upvalues[uv].name);
  if (s == NULL) return "?";
  else return getstr(s);
}


static const char *findvararg (CallInfo *ci, int n, StkId *pos) {
  if (clLvalue(s2v(ci->func))->p->is_vararg) {
    int nextra = ci->u.l.nextraargs;
    if (n <= nextra) {
      *pos = ci->func - nextra + (n - 1);
      return "(vararg)";  /* generic name for any vararg */
    }
  }
  return NULL;  /* no such vararg */
}


const char *luaG_findlocal (lua_State *L, CallInfo *ci, int n, StkId *pos) {
  StkId base = ci->func + 1;
  const char *name = NULL;
  if (isLua(ci)) {
    if (n < 0)  /* access to vararg values? */
      return findvararg(ci, -n, pos);
    else
      name = luaF_getlocalname(ci_func(ci)->p, n, currentpc(ci));
  }
  if (name == NULL) {  /* no 'standard' name? */
    StkId limit = (ci == L->ci) ? L->top : ci->next->func;
    if (limit - base >= n && n > 0) {  /* is 'n' inside 'ci' stack? */
      /* generic name for any valid slot */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,8 +188,8 @@
 static const char *findvararg (CallInfo *ci, int n, StkId *pos) {
   if (clLvalue(s2v(ci->func))->p->is_vararg) {
     int nextra = ci->u.l.nextraargs;
-    if (n <= nextra) {
-      *pos = ci->func - nextra + (n - 1);
+    if (n >= -nextra) {  /* 'n' is negative */
+      *pos = ci->func - nextra - (n + 1);
       return "(vararg)";  /* generic name for any vararg */
     }
   }
@@ -202,7 +202,7 @@
   const char *name = NULL;
   if (isLua(ci)) {
     if (n < 0)  /* access to vararg values? */
-      return findvararg(ci, -n, pos);
+      return findvararg(ci, n, pos);
     else
       name = luaF_getlocalname(ci_func(ci)->p, n, currentpc(ci));
   }
```
