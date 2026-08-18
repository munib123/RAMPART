# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1570_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1570_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 40-59 of the vulnerable file.

    char *base = strrchr((abspath ? abspath : filename), '/');

    /* If realpath failed and filename is malicious (say, "/foo/.."),
     * we may end up tricked into doing some bad things. Don't allow that.
     */
    char buf[sizeof("tmp-"LIBREPORT_ISO_DATE_STRING_SAMPLE"-%lu")];
    if (base && base[1] != '\0' && base[1] != '.')
    {
        /* We have a slash and it's not "foo/" or "foo/.<something>" */
        base++;
    }
    else
    {
        sprintf(buf, "tmp-%s-%lu", iso_date_string(NULL), (long)getpid());
        base = buf;
    }
    char *name = concat_path_file(path, base);
    free(abspath);
    return name;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,3 +57,28 @@
     free(abspath);
     return name;
 }
+
+bool str_is_correct_filename(const char *str)
+{
+#define NOT_PRINTABLE(c) (c < ' ' || c == 0x7f)
+
+    if (NOT_PRINTABLE(*str) || *str == '/' || *str == '\0')
+        return false;
+    ++str;
+
+    if (NOT_PRINTABLE(*str) || *str =='/' || (*str == '\0' && *(str-1) == '.'))
+        return false;
+    ++str;
+
+    if (NOT_PRINTABLE(*str) || *str =='/' || (*str == '\0' && *(str-1) == '.' && *(str-2) == '.'))
+        return false;
+    ++str;
+
+    for (unsigned i = 0; *str != '\0' && i < 61; ++str, ++i)
+        if (NOT_PRINTABLE(*str) || *str == '/')
+            return false;
+
+    return *str == '\0';
+
+#undef NOT_PRINTABLE
+}
```
