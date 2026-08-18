# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 3576_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3576_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 108-149 of the vulnerable file.

        requested = MIN (size < max_len ? max_len - size : 0,
                         alloc - size - 1);
        count = fread (buf + size, 1, requested, stream);
        size += count;

        if (count != requested || requested == 0) {
            save_errno = errno;
            if (ferror (stream))
                break;
            buf[size] = '\0';
            *length = size;
            return buf;
        }
    }

    free (buf);
    errno = save_errno;
    return NULL;
}

char* xread_file(const char *path) {
    FILE *fp = fopen(path, "r");
    char *result;
    size_t len;

    if (!fp)
        return NULL;

    result = fread_file_lim(fp, MAX_READ_LEN, &len);
    fclose (fp);

    if (result != NULL
        && len <= MAX_READ_LEN
        && (int) len == len)
        return result;

    free(result);
    return NULL;
}

/*
 * Escape/unescape of string literals
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,8 +125,7 @@
     return NULL;
 }
 
-char* xread_file(const char *path) {
-    FILE *fp = fopen(path, "r");
+char* xfread_file(FILE *fp) {
     char *result;
     size_t len;
 
@@ -134,7 +133,6 @@
         return NULL;
 
     result = fread_file_lim(fp, MAX_READ_LEN, &len);
-    fclose (fp);
 
     if (result != NULL
         && len <= MAX_READ_LEN
@@ -143,6 +141,17 @@
 
     free(result);
     return NULL;
+}
+
+char* xread_file(const char *path) {
+    FILE *fp;
+    char *result;
+
+    fp = fopen(path, "r");
+    result = xfread_file(fp);
+    fclose (fp);
+
+    return result;
 }
 
 /*
```
