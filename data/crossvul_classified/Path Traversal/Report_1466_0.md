# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1466_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1466_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 3503-3543 of the vulnerable file.

        list_info();
        RELEASE(g.hname);
        if (g.ind != 0)
            close(g.ind);
        return;
    }

    /* create output file out, descriptor outd */
    if (path == NULL || g.pipeout) {
        /* write to stdout */
        g.outf = MALLOC(strlen("<stdout>") + 1);
        if (g.outf == NULL)
            bail("not enough memory", "");
        strcpy(g.outf, "<stdout>");
        g.outd = 1;
        if (!g.decode && !g.force && isatty(g.outd))
            bail("trying to write compressed data to a terminal",
                 " (use -f to force)");
    }
    else {
        char *to, *repl;

        /* use header name for output when decompressing with -N */
        to = g.inf;
        if (g.decode && (g.headis & 1) != 0 && g.hname != NULL) {
            to = g.hname;
            len = strlen(g.hname);
        }

        /* replace .tgz with .tar when decoding */
        repl = g.decode && strcmp(to + len, ".tgz") ? "" : ".tar";

        /* create output file and open to write */
        g.outf = MALLOC(len + (g.decode ? strlen(repl) : strlen(g.sufx)) + 1);
        if (g.outf == NULL)
            bail("not enough memory", "");
        memcpy(g.outf, to, len);
        strcpy(g.outf + len, g.decode ? repl : g.sufx);
        g.outd = open(g.outf, O_CREAT | O_TRUNC | O_WRONLY |
                             (g.force ? 0 : O_EXCL), 0600);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3520,26 +3520,35 @@
                  " (use -f to force)");
     }
     else {
-        char *to, *repl;
-
-        /* use header name for output when decompressing with -N */
-        to = g.inf;
-        if (g.decode && (g.headis & 1) != 0 && g.hname != NULL) {
-            to = g.hname;
-            len = strlen(g.hname);
-        }
-
-        /* replace .tgz with .tar when decoding */
-        repl = g.decode && strcmp(to + len, ".tgz") ? "" : ".tar";
+        char *to = g.inf, *sufx = "";
+        size_t pre = 0;
+
+        /* select parts of the output file name */
+        if (g.decode) {
+            /* for -dN or -dNT, use the path from the input file and the name
+               from the header, stripping any path in the header name */
+            if ((g.headis & 1) != 0 && g.hname != NULL) {
+                pre = justname(g.inf) - g.inf;
+                to = justname(g.hname);
+                len = strlen(to);
+            }
+            /* for -d or -dNn, replace abbreviated suffixes */
+            else if (strcmp(to + len, ".tgz") == 0)
+                sufx = ".tar";
+        }
+        else
+            /* add appropriate suffix when compressing */
+            sufx = g.sufx;
 
         /* create output file and open to write */
-        g.outf = MALLOC(len + (g.decode ? strlen(repl) : strlen(g.sufx)) + 1);
+        g.outf = MALLOC(pre + len + strlen(sufx) + 1);
         if (g.outf == NULL)
             bail("not enough memory", "");
-        memcpy(g.outf, to, len);
-        strcpy(g.outf + len, g.decode ? repl : g.sufx);
+        memcpy(g.outf, g.inf, pre);
+        memcpy(g.outf + pre, to, len);
+        strcpy(g.outf + pre + len, sufx);
         g.outd = open(g.outf, O_CREAT | O_TRUNC | O_WRONLY |
-                             (g.force ? 0 : O_EXCL), 0600);
+                              (g.force ? 0 : O_EXCL), 0600);
 
         /* if exists and not -f, give user a chance to overwrite */
         if (g.outd < 0 && errno == EEXIST && isatty(0) && g.verbosity) {
```
