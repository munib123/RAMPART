# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1005_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1005_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 105-145 of the vulnerable file.

static void add_kid(int id, xref_t *xref);
static void load_kids(FILE *fp, int pages_id, xref_t *xref);

static const char *get_type(FILE *fp, int obj_id, const xref_t *xref);
/* static int get_page(int obj_id, const xref_t *xref); */
static char *get_header(FILE *fp);

static char *decode_text_string(const char *str, size_t str_len);
static int get_next_eof(FILE *fp);


/*
 * Defined
 */

pdf_t *pdf_new(const char *name)
{
    const char *n;
    pdf_t      *pdf;
   
    pdf = calloc(1, sizeof(pdf_t));

    if (name)
    {
        /* Just get the file name (not path) */
        if ((n = strrchr(name, '/')))
          ++n;
        else
          n = name;

        pdf->name = malloc(strlen(n) + 1);
        strcpy(pdf->name, n);
    }
    else /* !name */
    {
        pdf->name = malloc(strlen("Unknown") + 1);
        strcpy(pdf->name, "Unknown");
    }

    return pdf;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,7 +122,7 @@
     const char *n;
     pdf_t      *pdf;
    
-    pdf = calloc(1, sizeof(pdf_t));
+    pdf = safe_calloc(sizeof(pdf_t));
 
     if (name)
     {
@@ -132,12 +132,12 @@
         else
           n = name;
 
-        pdf->name = malloc(strlen(n) + 1);
+        pdf->name = safe_calloc(strlen(n) + 1);
         strcpy(pdf->name, n);
     }
     else /* !name */
     {
-        pdf->name = malloc(strlen("Unknown") + 1);
+        pdf->name = safe_calloc(strlen("Unknown") + 1);
         strcpy(pdf->name, "Unknown");
     }
 
@@ -216,7 +216,7 @@
 
     /* Load in the start/end positions */
     fseek(fp, 0, SEEK_SET);
-    pdf->xrefs = calloc(1, sizeof(xref_t) * pdf->n_xrefs);
+    pdf->xrefs = safe_calloc(sizeof(xref_t) * pdf->n_xrefs);
     ver = 1;
     for (i=0; i<pdf->n_xrefs; i++)
     {
@@ -314,7 +314,7 @@
 
             /* Get root catalog */
             sz = pdf->xrefs[i].end - ftell(fp);
-            buf = malloc(sz + 1);
+            buf = safe_calloc(sz + 1);
             SAFE_E(fread(buf, 1, sz, fp), sz, "Failed to load /Root.\n");
             buf[sz] = '\0';
             if (!(c = strstr(buf, "/Root")))
@@ -444,7 +444,7 @@
 
     if (name)
     {
-        dst_name = malloc(strlen(name) * 2 + 16);
+        dst_name = safe_calloc(strlen(name) * 2 + 16);
         sprintf(dst_name, "%s/%s", name, name);
 
         if ((c = strrchr(dst_name, '.')) && (strncmp(c, ".pdf", 4) == 0))
@@ -643,7 +643,7 @@
 
     SAFE_E(fread(buf, 1, 21, fp), 21, "Failed to load entry Size string.\n");
     xref->n_entries = atoi(buf + strlen("ize "));
-    xref->entries = calloc(1, xref->n_entries * sizeof(struct _xref_entry));
+    xref->entries = safe_calloc(xref->n_entries * sizeof(struct _xref_entry));
 
     /* Load entry data */
     obj_id = 0;
@@ -810,7 +810,7 @@
         {"Trapped",      ""},
     };
 
-    daddy = malloc(sizeof(creator_template));
+    daddy = safe_calloc(sizeof(creator_template));
     memcpy(daddy, creator_template, sizeof(creator_template));
 
     if (n_elements)
@@ -1099,8 +1099,7 @@
     obj_sz = 0;    /* Bytes in object */
     total_sz = 0;  /* Bytes read in   */
     n_blks = 1;
-    data = malloc(blk_sz * n_blks);
-    memset(data, 0, blk_sz * n_blks);
+    data = safe_calloc(blk_sz * n_blks);
 
     /* Suck in data */
     stream = 0;
@@ -1266,18 +1265,12 @@
 
 static char *get_header(FILE *fp)
 {
-    long start;
-
     /* First 1024 bytes of doc must be header (1.7 spec pg 1102) */
-    char *header;
-
-    header = calloc(1, 1024);
-    
-    start = ftell(fp);
+    char *header = safe_calloc(1024);
+    long start = ftell(fp);
     fseek(fp, 0, SEEK_SET);
     SAFE_E(fread(header, 1, 1023, fp), 1023, "Failed to load PDF header.\n");
     fseek(fp, start, SEEK_SET);
-    
     return header;
 }
 
@@ -1292,7 +1285,7 @@
     /* Regular encoding */
     if (str[0] == '(')
     {
-        ascii = malloc(strlen(str) + 1);
+        ascii = safe_calloc(strlen(str) + 1);
         strncpy(ascii, str, strlen(str) + 1);
         return ascii;
     }
@@ -1314,7 +1307,7 @@
       return NULL;
 
     /* Now decode as hex */
-    ascii = malloc(str_len);
+    ascii = safe_calloc(str_len);
     for ( ; idx<str_len; ++idx)
     {
         hex_buf[0] = str[idx++];
```
