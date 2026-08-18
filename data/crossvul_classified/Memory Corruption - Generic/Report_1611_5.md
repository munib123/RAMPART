# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1611_5
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1611_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 353-393 of the vulnerable file.

    n = (len + rbufpos <= MAX_RSRC_LEN ? len : MAX_RSRC_LEN - rbufpos);
    memcpy(rbuf + rbufpos, s, n);
    rbufpos += n;
    s += n;
    len -= n;
  }
}

static void
t1mac_output_ascii(char *s, int len)
{
  if (blocktyp == POST_BINARY) {
    output_current_post();
    blocktyp = POST_ASCII;
  }
  /* Mac line endings */
  if (len > 0 && s[len-1] == '\n')
    s[len-1] = '\r';
  t1mac_output_data((byte *)s, len);
  if (strncmp(s, "/FontName", 9) == 0) {
    for (s += 9; isspace(*s); s++) ;
    if (*s == '/') {
      const char *t = ++s;
      while (*t && !isspace(*t)) t++;
      free(font_name);
      font_name = (char *)malloc(t - s + 1);
      memcpy(font_name, s, t - s);
      font_name[t - s] = 0;
    }
  }
}

static void
t1mac_output_binary(unsigned char *s, int len)
{
  if (blocktyp == POST_ASCII) {
    output_current_post();
    blocktyp = POST_BINARY;
  }
  t1mac_output_data(s, len);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -370,10 +370,11 @@
     s[len-1] = '\r';
   t1mac_output_data((byte *)s, len);
   if (strncmp(s, "/FontName", 9) == 0) {
-    for (s += 9; isspace(*s); s++) ;
+    for (s += 9; isspace((unsigned char) *s); s++)
+        /* skip */;
     if (*s == '/') {
       const char *t = ++s;
-      while (*t && !isspace(*t)) t++;
+      while (*t && !isspace((unsigned char) *t)) t++;
       free(font_name);
       font_name = (char *)malloc(t - s + 1);
       memcpy(font_name, s, t - s);
@@ -994,11 +995,11 @@
     int part = 0, len = 0;
     char *x, *s;
     for (x = s = font_name; *s; s++)
-      if (isupper(*s) || isdigit(*s)) {
+      if (isupper((unsigned char) *s) || isdigit((unsigned char) *s)) {
 	*x++ = *s;
 	part++;
 	len = 1;
-      } else if (islower(*s)) {
+      } else if (islower((unsigned char) *s)) {
 	if (len < (part <= 1 ? 5 : 3))
 	  *x++ = *s;
 	len++;
```
