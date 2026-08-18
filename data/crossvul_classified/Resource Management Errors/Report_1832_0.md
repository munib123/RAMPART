# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1832_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1832_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1070-1110 of the vulnerable file.

        }
        gdImageSetInterpolationMethod(tmp_im, src->interpolation_id);

        _gdScalePass(src, src_width, tmp_im, new_width, src_height, HORIZONTAL);
    }/* if .. else*/

    /* If vertical sizes match, we're done. */
    if (src_height == new_height) {
        assert(tmp_im != src);
        return tmp_im;
    }/* if */

    /* Otherwise, we need to scale vertically. */
	dst = gdImageCreateTrueColor(new_width, new_height);
	if (dst != NULL) {
        gdImageSetInterpolationMethod(dst, src->interpolation_id);
        _gdScalePass(tmp_im, src_height, dst, new_height, new_width, VERTICAL);
    }/* if */

    if (src != tmp_im) {
        gdFree(tmp_im);
    }/* if */

	return dst;
}/* gdImageScaleTwoPass*/


/*
	BilinearFixed, BicubicFixed and nearest implementations are
	rewamped versions of the implementation in CBitmapEx

	http://www.codeproject.com/Articles/29121/CBitmapEx-Free-C-Bitmap-Manipulation-Class

	Integer only implementation, good to have for common usages like
	pre scale very large images before using another interpolation
	methods for the last step.
*/
static gdImagePtr
gdImageScaleNearestNeighbour(gdImagePtr im, const unsigned int width, const unsigned int height)
{
	const unsigned long new_width = MAX(1, width);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1087,7 +1087,7 @@
     }/* if */
 
     if (src != tmp_im) {
-        gdFree(tmp_im);
+        gdImageDestroy(tmp_im);
     }/* if */
 
 	return dst;
```
