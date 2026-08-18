# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 131_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `131_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 276-316 of the vulnerable file.

      l <<= 8;
      l |= (Uinttype)(unsigned char)buff[i];
    }
  }
  if (!issigned)
    return (lua_Number)l;
  else {  /* signed format */
    Uinttype mask = (Uinttype)(~((Uinttype)0)) << (size*8 - 1);
    if (l & mask)  /* negative value? */
      l |= mask;  /* signal extension */
    return (lua_Number)(Inttype)l;
  }
}


static int b_unpack (lua_State *L) {
  Header h;
  const char *fmt = luaL_checkstring(L, 1);
  size_t ld;
  const char *data = luaL_checklstring(L, 2, &ld);
  size_t pos = luaL_optinteger(L, 3, 1) - 1;
  int n = 0;  /* number of results */
  defaultoptions(&h);
  while (*fmt) {
    int opt = *fmt++;
    size_t size = optsize(L, opt, &fmt);
    pos += gettoalign(pos, &h, opt, size);
    luaL_argcheck(L, pos+size <= ld, 2, "data string too short");
    /* stack space for item + next position */
    luaL_checkstack(L, 2, "too many results");
    switch (opt) {
      case 'b': case 'B': case 'h': case 'H':
      case 'l': case 'L': case 'T': case 'i':  case 'I': {  /* integer types */
        int issigned = islower(opt);
        lua_Number res = getinteger(data+pos, h.endian, issigned, size);
        lua_pushnumber(L, res); n++;
        break;
      }
      case 'x': {
        break;
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -293,14 +293,18 @@
   const char *fmt = luaL_checkstring(L, 1);
   size_t ld;
   const char *data = luaL_checklstring(L, 2, &ld);
-  size_t pos = luaL_optinteger(L, 3, 1) - 1;
+  size_t pos = luaL_optinteger(L, 3, 1);
+  luaL_argcheck(L, pos > 0, 3, "offset must be 1 or greater");
+  pos--; /* Lua indexes are 1-based, but here we want 0-based for C
+          * pointer math. */
   int n = 0;  /* number of results */
   defaultoptions(&h);
   while (*fmt) {
     int opt = *fmt++;
     size_t size = optsize(L, opt, &fmt);
     pos += gettoalign(pos, &h, opt, size);
-    luaL_argcheck(L, pos+size <= ld, 2, "data string too short");
+    luaL_argcheck(L, size <= ld && pos <= ld - size,
+                   2, "data string too short");
     /* stack space for item + next position */
     luaL_checkstack(L, 2, "too many results");
     switch (opt) {
```
