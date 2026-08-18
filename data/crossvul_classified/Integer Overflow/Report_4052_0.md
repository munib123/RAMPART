# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4052_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4052_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 72-112 of the vulnerable file.

#define MAXALIGN  	(PADDING > sizeof(int) ? PADDING : sizeof(int))


/* endian options */
#define BIG	0
#define LITTLE	1


static union {
  int dummy;
  char endian;
} const native = {1};


typedef struct Header {
  int endian;
  int align;
} Header;


static int getnum (const char **fmt, int df) {
  if (!isdigit(**fmt))  /* no number? */
    return df;  /* return default value */
  else {
    int a = 0;
    do {
      a = a*10 + *((*fmt)++) - '0';
    } while (isdigit(**fmt));
    return a;
  }
}


#define defaultoptions(h)	((h)->endian = native.endian, (h)->align = 1)



static size_t optsize (lua_State *L, char opt, const char **fmt) {
  switch (opt) {
    case 'B': case 'b': return sizeof(char);
    case 'H': case 'h': return sizeof(short);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,12 +89,14 @@
 } Header;
 
 
-static int getnum (const char **fmt, int df) {
+static int getnum (lua_State *L, const char **fmt, int df) {
   if (!isdigit(**fmt))  /* no number? */
     return df;  /* return default value */
   else {
     int a = 0;
     do {
+      if (a > (INT_MAX / 10) || a * 10 > (INT_MAX - (**fmt - '0')))
+        luaL_error(L, "integral size overflow");
       a = a*10 + *((*fmt)++) - '0';
     } while (isdigit(**fmt));
     return a;
@@ -115,9 +117,9 @@
     case 'f':  return sizeof(float);
     case 'd':  return sizeof(double);
     case 'x': return 1;
-    case 'c': return getnum(fmt, 1);
+    case 'c': return getnum(L, fmt, 1);
     case 'i': case 'I': {
-      int sz = getnum(fmt, sizeof(int));
+      int sz = getnum(L, fmt, sizeof(int));
       if (sz > MAXINTSIZE)
         luaL_error(L, "integral size %d is larger than limit of %d",
                        sz, MAXINTSIZE);
@@ -150,7 +152,7 @@
     case '>': h->endian = BIG; return;
     case '<': h->endian = LITTLE; return;
     case '!': {
-      int a = getnum(fmt, MAXALIGN);
+      int a = getnum(L, fmt, MAXALIGN);
       if (!isp2(a))
         luaL_error(L, "alignment %d is not a power of 2", a);
       h->align = a;
```
