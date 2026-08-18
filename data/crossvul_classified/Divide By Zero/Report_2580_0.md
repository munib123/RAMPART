# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 2580_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2580_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 1400-1440 of the vulnerable file.

typedef struct _RsvgFilterPrimitiveGaussianBlur
 RsvgFilterPrimitiveGaussianBlur;

struct _RsvgFilterPrimitiveGaussianBlur {
    RsvgFilterPrimitive super;
    double sdx, sdy;
};

static void
box_blur_line (gint box_width, gint even_offset,
               guchar *src, guchar *dest,
               gint len, gint bpp)
{
    gint  i;
    gint  lead;    /* This marks the leading edge of the kernel              */
    gint  output;  /* This marks the center of the kernel                    */
    gint  trail;   /* This marks the pixel BEHIND the last 1 in the
                      kernel; it's the pixel to remove from the accumulator. */
    gint  *ac;     /* Accumulator for each channel                           */

    ac = g_new0 (gint, bpp);

    /* The algorithm differs for even and odd-sized kernels.
     * With the output at the center,
     * If odd, the kernel might look like this: 0011100
     * If even, the kernel will either be centered on the boundary between
     * the output and its left neighbor, or on the boundary between the
     * output and its right neighbor, depending on even_lr.
     * So it might be 0111100 or 0011110, where output is on the center
     * of these arrays.
     */
    lead = 0;

    if (box_width % 2 != 0) {
        /* Odd-width kernel */
        output = lead - (box_width - 1) / 2;
        trail  = lead - box_width;
    } else {
        /* Even-width kernel. */
        if (even_offset == 1) {
            /* Right offset */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1417,6 +1417,8 @@
                       kernel; it's the pixel to remove from the accumulator. */
     gint  *ac;     /* Accumulator for each channel                           */
 
+    g_assert (box_width > 0);
+
     ac = g_new0 (gint, bpp);
 
     /* The algorithm differs for even and odd-sized kernels.
@@ -1774,7 +1776,6 @@
                        gdouble sx,
                        gdouble sy)
 {
-    gboolean use_box_blur;
     gint width, height;
     cairo_format_t in_format, out_format;
     gint in_stride;
@@ -1818,14 +1819,6 @@
     if (sy < 0.0)
         sy = 0.0;
 
-    /* For small radiuses, use a true gaussian kernel; otherwise use three box blurs with
-     * clever offsets.
-     */
-    if (sx < 10.0 && sy < 10.0)
-        use_box_blur = FALSE;
-    else
-        use_box_blur = TRUE;
-
     /* Bail out by just copying? */
     if ((sx == 0.0 && sy == 0.0)
         || sx > 1000 || sy > 1000) {
@@ -1845,6 +1838,15 @@
         int y;
         guchar *row_buffer = NULL;
         guchar *row1, *row2;
+        gboolean use_box_blur;
+
+        /* For small radiuses, use a true gaussian kernel; otherwise use three box blurs with
+         * clever offsets.
+         */
+        if (sx < 10.0)
+            use_box_blur = FALSE;
+        else
+            use_box_blur = TRUE;
 
         if (use_box_blur) {
             box_width = compute_box_blur_width (sx);
@@ -1900,6 +1902,15 @@
         guchar *col_buffer;
         guchar *col1, *col2;
         int x;
+        gboolean use_box_blur;
+
+        /* For small radiuses, use a true gaussian kernel; otherwise use three box blurs with
+         * clever offsets.
+         */
+        if (sy < 10.0)
+            use_box_blur = FALSE;
+        else
+            use_box_blur = TRUE;
 
         /* twice the size so we can have the source pixels and the blurred pixels */
         col_buffer = g_new0 (guchar, height * bpp * 2);
```
