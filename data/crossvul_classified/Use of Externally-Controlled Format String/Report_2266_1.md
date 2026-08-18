# CrossVul Fix Pair: Use of Externally-Controlled Format String in c
**Pair ID:** 2266_1
**Vulnerability Class:** Use of Externally-Controlled Format String
**CWE:** CWE-134
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2266_1`)

## Vulnerability Information & PoC

## Description
Use of Externally-Controlled Format String - When an attacker can modify an externally-controlled format string, this can lead to buffer overflows, denial of service, or data representation problems.

## Vulnerable Code
```c
Lines 379-419 of the vulnerable file.

    const char *const,
    int,
    char *const);
void      rrd_graph_init(
    image_desc_t *);

void      rrd_graph_options(
    int,
    char **,
    image_desc_t *);
void      rrd_graph_script(
    int,
    char **,
    image_desc_t *,
    int);
int       rrd_graph_color(
    image_desc_t *,
    char *,
    char *,
    int);
int       bad_format(
    char *);
int       vdef_parse(
    struct graph_desc_t *,
    const char *const);
int       vdef_calc(
    image_desc_t *,
    int);
int       vdef_percent_compar(
    const void *,
    const void *);
int       graph_size_location(
    image_desc_t *,
    int);


/* create a new line */
void      gfx_line(
    image_desc_t *im,
    double X0,
    double Y0,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -396,7 +396,11 @@
     char *,
     char *,
     int);
-int       bad_format(
+int       bad_format_axis(
+    char *);
+int       bad_format_print(
+    char *);
+int       bad_format_imginfo(
     char *);
 int       vdef_parse(
     struct graph_desc_t *,
```
