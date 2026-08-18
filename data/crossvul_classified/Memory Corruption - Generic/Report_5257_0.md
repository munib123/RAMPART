# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5257_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5257_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 3065-3105 of the vulnerable file.

	} else {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Color index %d out of range", col);
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto bool imagegammacorrect(resource im, float inputgamma, float outputgamma)
   Apply a gamma correction to a GD image */
PHP_FUNCTION(imagegammacorrect)
{
	zval *IM;
	gdImagePtr im;
	int i;
	double input, output;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rdd", &IM, &input, &output) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);

	if (gdImageTrueColor(im))	{
		int x, y, c;

		for (y = 0; y < gdImageSY(im); y++)	{
			for (x = 0; x < gdImageSX(im); x++)	{
				c = gdImageGetPixel(im, x, y);
				gdImageSetPixel(im, x, y,
					gdTrueColorAlpha(
						(int) ((pow((pow((gdTrueColorGetRed(c)   / 255.0), input)), 1.0 / output) * 255) + .5),
						(int) ((pow((pow((gdTrueColorGetGreen(c) / 255.0), input)), 1.0 / output) * 255) + .5),
						(int) ((pow((pow((gdTrueColorGetBlue(c)  / 255.0), input)), 1.0 / output) * 255) + .5),
						gdTrueColorGetAlpha(c)
					)
				);
			}
		}
		RETURN_TRUE;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3082,6 +3082,11 @@
 		return;
 	}
 
+	if ( input <= 0.0 || output <= 0.0 ) {
+		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Gamma values should be positive");
+		RETURN_FALSE;
+	}
+
 	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);
 
 	if (gdImageTrueColor(im))	{
```
