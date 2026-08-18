# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1826_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1826_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 366-406 of the vulnerable file.

        p->output = JV_ARRAY(jv_copy(p->path));
    }
    p->path = jv_array_slice(p->path, 0, --(p->stacklen)); // pop
    jv_free(p->next);
    p->next = jv_invalid();

    if (p->last_seen == JV_LAST_OPEN_OBJECT)
      p->output = JV_ARRAY(jv_copy(p->path), jv_object()); // Empty arrays are leaves

    if (p->stacklen == 0)
      p->last_seen = JV_LAST_NONE;
    else
      p->last_seen = JV_LAST_VALUE;
    break;
  }
  return 0;
}

static void tokenadd(struct jv_parser* p, char c) {
  assert(p->tokenpos <= p->tokenlen);
  if (p->tokenpos == p->tokenlen) {
    p->tokenlen = p->tokenlen*2 + 256;
    p->tokenbuf = jv_mem_realloc(p->tokenbuf, p->tokenlen);
  }
  assert(p->tokenpos < p->tokenlen);
  p->tokenbuf[p->tokenpos++] = c;
}

static int unhex4(char* hex) {
  int r = 0;
  for (int i=0; i<4; i++) {
    char c = *hex++;
    int n;
    if ('0' <= c && c <= '9') n = c - '0';
    else if ('a' <= c && c <= 'f') n = c - 'a' + 10;
    else if ('A' <= c && c <= 'F') n = c - 'A' + 10;
    else return -1;
    r <<= 4;
    r |= n;
  }
  return r;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -383,7 +383,7 @@
 
 static void tokenadd(struct jv_parser* p, char c) {
   assert(p->tokenpos <= p->tokenlen);
-  if (p->tokenpos == p->tokenlen) {
+  if (p->tokenpos >= (p->tokenlen - 1)) {
     p->tokenlen = p->tokenlen*2 + 256;
     p->tokenbuf = jv_mem_realloc(p->tokenbuf, p->tokenlen);
   }
@@ -485,7 +485,7 @@
     TRY(value(p, v));
   } else {
     // FIXME: better parser
-    p->tokenbuf[p->tokenpos] = 0; // FIXME: invalid
+    p->tokenbuf[p->tokenpos] = 0;
     char* end = 0;
     double d = jvp_strtod(&p->dtoa, p->tokenbuf, &end);
     if (end == 0 || *end != 0)
```
