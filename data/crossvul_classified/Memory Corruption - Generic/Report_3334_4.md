# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 3334_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3334_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 115-155 of the vulnerable file.

                nPreviewHeight = 1;
            }
        }

        for( cinfo.scale_denom = 1; cinfo.scale_denom < 8; cinfo.scale_denom *= 2 )
        {
            if( cinfo.image_width < nPreviewWidth * cinfo.scale_denom )
                break;
            if( cinfo.image_height < nPreviewHeight * cinfo.scale_denom )
                break;
        }

        if( cinfo.scale_denom > 1 )
        {
            cinfo.dct_method            = JDCT_FASTEST;
            cinfo.do_fancy_upsampling   = FALSE;
            cinfo.do_block_smoothing    = FALSE;
        }
    }

    jpeg_start_decompress( &cinfo );

    long nWidth = cinfo.output_width;
    long nHeight = cinfo.output_height;

    bool bGray = (cinfo.output_components == 1);

    JPEGCreateBitmapParam aCreateBitmapParam;

    aCreateBitmapParam.nWidth = nWidth;
    aCreateBitmapParam.nHeight = nHeight;

    aCreateBitmapParam.density_unit = cinfo.density_unit;
    aCreateBitmapParam.X_density = cinfo.X_density;
    aCreateBitmapParam.Y_density = cinfo.Y_density;
    aCreateBitmapParam.bGray = bGray;

    bool bBitmapCreated = pJPEGReader->CreateBitmap(aCreateBitmapParam);

    if (bBitmapCreated)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,7 +132,7 @@
         }
     }
 
-    jpeg_start_decompress( &cinfo );
+    jpeg_calc_output_dimensions(&cinfo);
 
     long nWidth = cinfo.output_width;
     long nHeight = cinfo.output_height;
@@ -161,7 +161,6 @@
             J_COLOR_SPACE best_out_color_space = JCS_RGB;
             ScanlineFormat eScanlineFormat = ScanlineFormat::N24BitTcRgb;
             ScanlineFormat eFinalFormat = pAccess->GetScanlineFormat();
-
             if (eFinalFormat == ScanlineFormat::N32BitTcBgra)
             {
                 best_out_color_space = JCS_EXT_BGRA;
@@ -190,9 +189,11 @@
                 cinfo.out_color_space != JCS_GRAYSCALE &&
                 cinfo.out_color_space != best_out_color_space)
             {
-                SAL_WARN("vcl.filter", "jpg with unknown out color space, forcing to :" << best_out_color_space);
+                SAL_WARN("vcl.filter", "jpg with unknown out color space, forcing to :" << best_out_color_space << " gray ");
                 cinfo.out_color_space = best_out_color_space;
             }
+
+            jpeg_start_decompress(&cinfo);
 
             JSAMPLE* aRangeLimit = cinfo.sample_range_limit;
 
```
