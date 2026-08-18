# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4263_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4263_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 159-199 of the vulnerable file.



void pdf_delete(pdf_t *pdf)
{
    int i;

    for (i=0; i<pdf->n_xrefs; i++)
    {
        free(pdf->xrefs[i].creator);
        free(pdf->xrefs[i].entries);
    }

    free(pdf->name);
    free(pdf->xrefs);
    free(pdf);
}


int pdf_is_pdf(FILE *fp)
{
    int   is_pdf;
    char *header;

    header = get_header(fp);

    if (header && strstr(header, "%PDF-"))
      is_pdf = 1;
    else 
      is_pdf = 0;

    free(header);
    return is_pdf;
}


void pdf_get_version(FILE *fp, pdf_t *pdf)
{
    char *header, *c;

    header = get_header(fp);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,16 +176,13 @@
 
 int pdf_is_pdf(FILE *fp)
 {
-    int   is_pdf;
     char *header;
-
-    header = get_header(fp);
-
-    if (header && strstr(header, "%PDF-"))
-      is_pdf = 1;
-    else 
-      is_pdf = 0;
-
+    if (!(header = get_header(fp)))
+      return 0;
+
+    /* First 1024 bytes of doc must be header (1.7 spec pg 1102) */
+    const char *c = strstr(header, "%PDF-");
+    const int is_pdf = c && ((c - header+strlen("%PDF-M.m")) < 1024);
     free(header);
     return is_pdf;
 }
@@ -193,13 +190,16 @@
 
 void pdf_get_version(FILE *fp, pdf_t *pdf)
 {
-    char *header, *c;
-
-    header = get_header(fp);
-
-    /* Locate version string start and make sure we dont go past header */
+    char *header = get_header(fp);
+
+    /* Locate version string start and make sure we dont go past header
+     * The format is %PDF-M.m, where 'M' is the major number and 'm' minor.
+     */
+    const char *c;
     if ((c = strstr(header, "%PDF-")) && 
-        (c + strlen("%PDF-M.m") + 2))
+        ((c + 6)[0] == '.') && // Separator
+        isdigit((c + 5)[0]) && // Major number
+        isdigit((c + 7)[0]))   // Minor number
     {
         pdf->pdf_major_version = atoi(c + strlen("%PDF-"));
         pdf->pdf_minor_version = atoi(c + strlen("%PDF-M."));
```
