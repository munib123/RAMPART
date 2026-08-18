# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 552_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `552_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 39-79 of the vulnerable file.

 * just passes all unsorted.
 */

int
scandir(const char *dir, struct dirent ***namelist,
        int (*select) (const struct dirent *),
        int (*compar) (const struct dirent **, const struct dirent **))
{
    DIR *d = opendir(dir);
    struct dirent *current;
    struct dirent **names;
    int count = 0;
    int pos = 0;
    int result = -1;

    if (NULL == d)
        return -1;

    while (NULL != readdir(d))
        count++;

    names = malloc(sizeof (struct dirent *) * count);

    closedir(d);
    d = opendir(dir);
    if (NULL == d)
        return -1;

    while (NULL != (current = readdir(d))) {
        if (NULL == select || select(current)) {
            struct dirent *copyentry = malloc(current->d_reclen);

            memcpy(copyentry, current, current->d_reclen);

            names[pos] = copyentry;
            pos++;
        }
    }
    result = closedir(d);

    if (pos != count)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,18 +56,26 @@
 
     while (NULL != readdir(d))
         count++;
+	
+	closedir(d);
+	
+    names = malloc(sizeof (struct dirent *) * count);
+	if (!names) 
+		return -1;
 
-    names = malloc(sizeof (struct dirent *) * count);
-
-    closedir(d);
     d = opendir(dir);
-    if (NULL == d)
+    if (NULL == d) {
+		free(names);
         return -1;
+    }
 
     while (NULL != (current = readdir(d))) {
         if (NULL == select || select(current)) {
             struct dirent *copyentry = malloc(current->d_reclen);
-
+			/* FIXME: OOM, silently skip it?*/
+			if (!copyentry)
+				continue;
+			
             memcpy(copyentry, current, current->d_reclen);
 
             names[pos] = copyentry;
```
