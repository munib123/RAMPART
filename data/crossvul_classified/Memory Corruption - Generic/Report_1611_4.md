# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1611_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1611_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 42-82 of the vulnerable file.

  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  else if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  else if (c >= '0' && c <= '9')
    return c - '0';
  else
    return 0;
}

/* This function translates a string of hexadecimal digits into binary data.
   We allow an odd number of digits. Returns length of binary data. */

static int
translate_hex_string(char *s, char *saved_orphan)
{
  int c1 = *saved_orphan;
  char *start = s;
  char *t = s;
  for (; *s; s++) {
    if (isspace(*s))
      continue;
    if (c1) {
      *t++ = (hexval(c1) << 4) + hexval(*s);
      c1 = 0;
    } else
      c1 = *s;
  }
  *saved_orphan = c1;
  return t - start;
}

/* This function returns 1 if the string contains all '0's. */

static int
all_zeroes(char *s)
{
  if (*s == '\0' || *s == '\n')
    return 0;
  while (*s == '0')
    s++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,7 +59,7 @@
   char *start = s;
   char *t = s;
   for (; *s; s++) {
-    if (isspace(*s))
+    if (isspace((unsigned char) *s))
       continue;
     if (c1) {
       *t++ = (hexval(c1) << 4) + hexval(*s);
@@ -136,10 +136,10 @@
 
 	/* now that we have the line, handle it */
 	if (blocktyp == PFA_ASCII) {
-	    if (strncmp(line, "currentfile eexec", 17) == 0 && isspace(line[17])) {
+	    if (strncmp(line, "currentfile eexec", 17) == 0 && isspace((unsigned char) line[17])) {
 		char saved_p;
 		/* assert(line == buffer); */
-		for (line += 18; isspace(*line); line++)
+		for (line += 18; isspace((unsigned char) *line); line++)
 		    /* nada */;
 		saved_p = *line;
 		*line = 0;
@@ -158,12 +158,14 @@
 	if (blocktyp == PFA_EEXEC_TEST) {
 	    /* 8.Feb.2004: fix bug if first character in a binary eexec block
 	       is 0, reported by Werner Lemberg */
-	    for (; line < last && isspace(*line); line++)
+	    for (; line < last && isspace((unsigned char) *line); line++)
 		/* nada */;
 	    if (line == last)
 		continue;
-	    else if (last >= line + 4 && isxdigit(line[0]) && isxdigit(line[1])
-		     && isxdigit(line[2]) && isxdigit(line[3]))
+	    else if (last >= line + 4 && isxdigit((unsigned char) line[0])
+                     && isxdigit((unsigned char) line[1])
+		     && isxdigit((unsigned char) line[2])
+                     && isxdigit((unsigned char) line[3]))
 		blocktyp = PFA_HEX;
 	    else
 		blocktyp = PFA_BINARY;
```
