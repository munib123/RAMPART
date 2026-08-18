# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2759_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2759_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 563-603 of the vulnerable file.

    unsigned char   colour_map_type;        /* Colour map type          */
    unsigned char   image_type;             /* Image type               */
    /*
    ** Colour map specification
    */
    unsigned short  colour_map_index;       /* First entry index        */
    unsigned short  colour_map_length;      /* Colour map length        */
    unsigned char   colour_map_entry_size;  /* Colour map entry size    */
    /*
    ** Image specification
    */
    unsigned short  x_origin;               /* x origin of image        */
    unsigned short  y_origin;               /* u origin of image        */
    unsigned short  image_width;            /* Image width              */
    unsigned short  image_height;           /* Image height             */
    unsigned char   pixel_depth;            /* Pixel depth              */
    unsigned char   image_desc;             /* Image descriptor         */
};
#endif /* INFORMATION_ONLY */

static unsigned short get_ushort(const unsigned char *data)
{
    unsigned short val = *(const unsigned short *)data;
#ifdef OPJ_BIG_ENDIAN
    val = ((val & 0xffU) << 8) | (val >> 8);
#endif
    return val;
}

#define TGA_HEADER_SIZE 18

static int tga_readheader(FILE *fp, unsigned int *bits_per_pixel,
                          unsigned int *width, unsigned int *height, int *flip_image)
{
    int palette_size;
    unsigned char tga[TGA_HEADER_SIZE];
    unsigned char id_len, /*cmap_type,*/ image_type;
    unsigned char pixel_depth, image_desc;
    unsigned short /*cmap_index,*/ cmap_len, cmap_entry_size;
    unsigned short /*x_origin, y_origin,*/ image_w, image_h;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -580,13 +580,10 @@
 };
 #endif /* INFORMATION_ONLY */
 
-static unsigned short get_ushort(const unsigned char *data)
-{
-    unsigned short val = *(const unsigned short *)data;
-#ifdef OPJ_BIG_ENDIAN
-    val = ((val & 0xffU) << 8) | (val >> 8);
-#endif
-    return val;
+/* Returns a ushort from a little-endian serialized value */
+static unsigned short get_tga_ushort(const unsigned char *data)
+{
+    return data[0] | (data[1] << 8);
 }
 
 #define TGA_HEADER_SIZE 18
@@ -613,17 +610,17 @@
     id_len = tga[0];
     /*cmap_type = tga[1];*/
     image_type = tga[2];
-    /*cmap_index = get_ushort(&tga[3]);*/
-    cmap_len = get_ushort(&tga[5]);
+    /*cmap_index = get_tga_ushort(&tga[3]);*/
+    cmap_len = get_tga_ushort(&tga[5]);
     cmap_entry_size = tga[7];
 
 
 #if 0
-    x_origin = get_ushort(&tga[8]);
-    y_origin = get_ushort(&tga[10]);
+    x_origin = get_tga_ushort(&tga[8]);
+    y_origin = get_tga_ushort(&tga[10]);
 #endif
-    image_w = get_ushort(&tga[12]);
-    image_h = get_ushort(&tga[14]);
+    image_w = get_tga_ushort(&tga[12]);
+    image_h = get_tga_ushort(&tga[14]);
     pixel_depth = tga[16];
     image_desc  = tga[17];
 
@@ -815,6 +812,24 @@
     } else {
         numcomps = save_alpha ? 4 : 3;
         color_space = OPJ_CLRSPC_SRGB;
+    }
+
+    /* If the declared file size is > 10 MB, check that the file is big */
+    /* enough to avoid excessive memory allocations */
+    if (image_height != 0 && image_width > 10000000 / image_height / numcomps) {
+        char ch;
+        OPJ_UINT64 expected_file_size =
+            (OPJ_UINT64)image_width * image_height * numcomps;
+        long curpos = ftell(f);
+        if (expected_file_size > (OPJ_UINT64)INT_MAX) {
+            expected_file_size = (OPJ_UINT64)INT_MAX;
+        }
+        fseek(f, (long)expected_file_size - 1, SEEK_SET);
+        if (fread(&ch, 1, 1, f) != 1) {
+            fclose(f);
+            return NULL;
+        }
+        fseek(f, curpos, SEEK_SET);
     }
 
     subsampling_dx = parameters->subsampling_dx;
```
