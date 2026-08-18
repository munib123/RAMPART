# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 622_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `622_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 672-712 of the vulnerable file.


    if ((fp = fopenReadStream(filename)) == NULL)
        return (PTA *)ERROR_PTR("stream not opened", procName, NULL);
    pta = ptaReadStream(fp);
    fclose(fp);
    if (!pta)
        return (PTA *)ERROR_PTR("pta not read", procName, NULL);
    return pta;
}


/*!
 * \brief   ptaReadStream()
 *
 * \param[in]    fp file stream
 * \return  pta, or NULL on error
 */
PTA *
ptaReadStream(FILE  *fp)
{
char       typestr[128];
l_int32    i, n, ix, iy, type, version;
l_float32  x, y;
PTA       *pta;

    PROCNAME("ptaReadStream");

    if (!fp)
        return (PTA *)ERROR_PTR("stream not defined", procName, NULL);

    if (fscanf(fp, "\n Pta Version %d\n", &version) != 1)
        return (PTA *)ERROR_PTR("not a pta file", procName, NULL);
    if (version != PTA_VERSION_NUMBER)
        return (PTA *)ERROR_PTR("invalid pta version", procName, NULL);
    if (fscanf(fp, " Number of pts = %d; format = %s\n", &n, typestr) != 2)
        return (PTA *)ERROR_PTR("not a pta file", procName, NULL);
    if (!strcmp(typestr, "float"))
        type = 0;
    else  /* typestr is "integer" */
        type = 1;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -689,7 +689,7 @@
 PTA *
 ptaReadStream(FILE  *fp)
 {
-char       typestr[128];
+char       typestr[128];  /* hardcoded below in fscanf */
 l_int32    i, n, ix, iy, type, version;
 l_float32  x, y;
 PTA       *pta;
@@ -703,7 +703,7 @@
         return (PTA *)ERROR_PTR("not a pta file", procName, NULL);
     if (version != PTA_VERSION_NUMBER)
         return (PTA *)ERROR_PTR("invalid pta version", procName, NULL);
-    if (fscanf(fp, " Number of pts = %d; format = %s\n", &n, typestr) != 2)
+    if (fscanf(fp, " Number of pts = %d; format = %127s\n", &n, typestr) != 2)
         return (PTA *)ERROR_PTR("not a pta file", procName, NULL);
     if (!strcmp(typestr, "float"))
         type = 0;
```
