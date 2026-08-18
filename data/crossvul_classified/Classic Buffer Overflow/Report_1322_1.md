# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 1322_1
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1322_1`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 2292-2332 of the vulnerable file.

        bufp = altp;

    return bufp;
}

boolean
parse_config_line(origbuf)
char *origbuf;
{
#if defined(MICRO) && !defined(NOCWD_ASSUMPTIONS)
    static boolean ramdisk_specified = FALSE;
#endif
#ifdef SYSCF
    int n, src = iflags.parse_config_file_src;
#endif
    char *bufp, buf[4 * BUFSZ];
    uchar translate[MAXPCHARS];
    int len;
    boolean retval = TRUE;

    /* convert any tab to space, condense consecutive spaces into one,
       remove leading and trailing spaces (exception: if there is nothing
       but spaces, one of them will be kept even though it leads/trails) */
    mungspaces(strcpy(buf, origbuf));

    /* find the '=' or ':' */
    bufp = find_optparam(buf);
    if (!bufp) {
        config_error_add("Not a config statement, missing '='");
        return FALSE;
    }
    /* skip past '=', then space between it and value, if any */
    ++bufp;
    if (*bufp == ' ')
        ++bufp;

    /* Go through possible variables */
    /* some of these (at least LEVELS and SAVE) should now set the
     * appropriate fqn_prefix[] rather than specialized variables
     */
    if (match_varname(buf, "OPTIONS", 4)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2309,10 +2309,14 @@
     int len;
     boolean retval = TRUE;
 
+    while (*origbuf == ' ' || *origbuf == '\t') /* skip leading whitespace */
+        ++origbuf;                   /* (caller probably already did this) */
+    (void) strncpy(buf, origbuf, sizeof buf - 1);
+    buf[sizeof buf - 1] = '\0'; /* strncpy not guaranteed to NUL terminate */
     /* convert any tab to space, condense consecutive spaces into one,
        remove leading and trailing spaces (exception: if there is nothing
        but spaces, one of them will be kept even though it leads/trails) */
-    mungspaces(strcpy(buf, origbuf));
+    mungspaces(buf);
 
     /* find the '=' or ':' */
     bufp = find_optparam(buf);
@@ -3034,7 +3038,11 @@
 proc_wizkit_line(buf)
 char *buf;
 {
-    struct obj *otmp = readobjnam(buf, (struct obj *) 0);
+    struct obj *otmp;
+
+    if (strlen(buf) >= BUFSZ)
+        buf[BUFSZ - 1] = '\0';
+    otmp = readobjnam(buf, (struct obj *) 0);
 
     if (otmp) {
         if (otmp != &zeroobj)
@@ -3142,22 +3150,23 @@
 
                 /* merge now read line with previous ones, if necessary */
                 if (!ignoreline) {
-                    len = (int) strlen(inbuf) + 1;
+                    len = (int) strlen(ep) + 1; /* +1: final '\0' */
                     if (buf)
-                        len += (int) strlen(buf);
+                        len += (int) strlen(buf) + 1; /* +1: space */
                     tmpbuf = (char *) alloc(len);
+                    *tmpbuf = '\0';
                     if (buf) {
-                        Sprintf(tmpbuf, "%s %s", buf, inbuf);
+                        Strcat(strcpy(tmpbuf, buf), " ");
                         free(buf);
-                    } else
-                        Strcpy(tmpbuf, inbuf);
-                    buf = tmpbuf;
+                    }
+                    buf = strcat(tmpbuf, ep);
+                    buf[sizeof inbuf - 1] = '\0';
                 }
 
                 if (morelines || (ignoreline && !oldline))
                     continue;
 
-                if (handle_config_section(ep)) {
+                if (handle_config_section(buf)) {
                     free(buf);
                     buf = (char *) 0;
                     continue;
@@ -3179,11 +3188,11 @@
                     }
                     bufp++;
                     if (config_section_chosen)
-                        free(config_section_chosen);
+                        free(config_section_chosen), config_section_chosen = 0;
                     section = choose_random_part(bufp, ',');
-                    if (section)
+                    if (section) {
                         config_section_chosen = dupstr(section);
-                    else {
+                    } else {
                         config_error_add("No config section to choose");
                         rv = FALSE;
                     }
@@ -3300,6 +3309,8 @@
     struct symparse *symp;
     char *bufp, *commentp, *altp;
 
+    if (strlen(buf) >= BUFSZ)
+        buf[BUFSZ - 1] = '\0';
     /* convert each instance of whitespace (tabs, consecutive spaces)
        into a single space; leading and trailing spaces are stripped */
     mungspaces(buf);
```
