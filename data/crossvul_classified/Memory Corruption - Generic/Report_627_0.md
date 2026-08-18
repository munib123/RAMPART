# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 627_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `627_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 154-194 of the vulnerable file.

        viewwidth = MIN_VIEW_WIDTH;
    }

        /* Make the output directory if it doesn't already exist */
#ifndef _WIN32
    snprintf(charbuf, sizeof(charbuf), "mkdir -p %s", dirout);
    ret = system(charbuf);
#else
    ret = CreateDirectory(dirout, NULL) ? 0 : 1;
#endif  /* !_WIN32 */
    if (ret) {
        L_ERROR("output directory %s not made\n", procName, dirout);
        return 1;
    }

        /* Capture the filenames in the input directory */
    if ((safiles = getFilenamesInDirectory(dirin)) == NULL)
        return ERROR_INT("safiles not made", procName, 1);

        /* Generate output text file names */
    sprintf(charbuf, "%s/%s.html", dirout, rootname);
    mainname = stringNew(charbuf);
    sprintf(charbuf, "%s/%s-links.html", dirout, rootname);
    linkname = stringNew(charbuf);
    linknameshort = stringJoin(rootname, "-links.html");

        /* Generate the thumbs and views */
    sathumbs = sarrayCreate(0);
    saviews = sarrayCreate(0);
    nfiles = sarrayGetCount(safiles);
    index = 0;
    for (i = 0; i < nfiles; i++) {
        fname = sarrayGetString(safiles, i, L_NOCOPY);
        fullname = genPathname(dirin, fname);
        fprintf(stderr, "name: %s\n", fullname);
        if ((pix = pixRead(fullname)) == NULL) {
            fprintf(stderr, "file %s not a readable image\n", fullname);
            lept_free(fullname);
            continue;
        }
        lept_free(fullname);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,9 +171,9 @@
         return ERROR_INT("safiles not made", procName, 1);
 
         /* Generate output text file names */
-    sprintf(charbuf, "%s/%s.html", dirout, rootname);
+    snprintf(charbuf, sizeof(charbuf), "%s/%s.html", dirout, rootname);
     mainname = stringNew(charbuf);
-    sprintf(charbuf, "%s/%s-links.html", dirout, rootname);
+    snprintf(charbuf, sizeof(charbuf), "%s/%s-links.html", dirout, rootname);
     linkname = stringNew(charbuf);
     linknameshort = stringJoin(rootname, "-links.html");
 
@@ -197,7 +197,7 @@
         pixGetDimensions(pix, &w, NULL, &d);
         factor = (l_float32)thumbwidth / (l_float32)w;
         pixthumb = pixScale(pix, factor, factor);
-        sprintf(charbuf, "%s_thumb_%03d", rootname, index);
+        snprintf(charbuf, sizeof(charbuf), "%s_thumb_%03d", rootname, index);
         sarrayAddString(sathumbs, charbuf, L_COPY);
         outname = genPathname(dirout, charbuf);
         WriteFormattedPix(outname, pixthumb);
```
