# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1005_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1005_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 55-95 of the vulnerable file.


    exit(0);
}


static void write_version(
    FILE       *fp,
    const char *fname,
    const char *dirname,
    xref_t     *xref)
{
    long  start;
    char *c, *new_fname, data;
    FILE *new_fp;
    
    start = ftell(fp);

    /* Create file */
    if ((c = strstr(fname, ".pdf")))
      *c = '\0';
    new_fname = malloc(strlen(fname) + strlen(dirname) + 16);
    snprintf(new_fname, strlen(fname) + strlen(dirname) + 16,
             "%s/%s-version-%d.pdf", dirname, fname, xref->version);

    if (!(new_fp = fopen(new_fname, "w")))
    {
        ERR("Could not create file '%s'\n", new_fname);
        fseek(fp, start, SEEK_SET);
        free(new_fname);
        return;
    }
    
    /* Copy original PDF */
    fseek(fp, 0, SEEK_SET);
    while (fread(&data, 1, 1, fp))
      fwrite(&data, 1, 1, new_fp);

    /* Emit an older startxref, refering to an older version. */
    fprintf(new_fp, "\r\nstartxref\r\n%ld\r\n%%%%EOF", xref->start);

    /* Clean */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,7 @@
     /* Create file */
     if ((c = strstr(fname, ".pdf")))
       *c = '\0';
-    new_fname = malloc(strlen(fname) + strlen(dirname) + 16);
+    new_fname = safe_calloc(strlen(fname) + strlen(dirname) + 16);
     snprintf(new_fname, strlen(fname) + strlen(dirname) + 16,
              "%s/%s-version-%d.pdf", dirname, fname, xref->version);
 
@@ -210,6 +210,23 @@
     pdf_load_pages_kids(fp, pdf);
 
     return pdf;
+}
+
+
+void *safe_calloc(size_t size) {
+  void *addr;
+
+  if (!size)
+  {
+    ERR("Invalid allocation size.\n");
+    exit(EXIT_FAILURE);
+  }
+  if (!(addr = calloc(1, size)))
+  {
+      ERR("Failed to allocate requested number of bytes, out of memory?\n");
+      exit(EXIT_FAILURE);
+  }
+  return addr;
 }
 
 
@@ -295,7 +312,7 @@
         if ((c = strrchr(name, '.')))
           *c = '\0';
 
-        dname = malloc(strlen(name) + 16);
+        dname = safe_calloc(strlen(name) + 16);
         sprintf(dname, "%s-versions", name);
         if (!(dir = opendir(dname)))
           mkdir(dname, S_IRWXU);
```
