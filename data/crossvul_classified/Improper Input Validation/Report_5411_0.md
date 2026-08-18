# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5411_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5411_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 171-211 of the vulnerable file.

      gdImagePtr im;
      im = gdImageCreate(64, 64);
      // ... Use the image ...
      gdImageDestroy(im);

      (end code)

    See Also:

        <gdImageCreateTrueColor>        

 */
BGD_DECLARE(gdImagePtr) gdImageCreate (int sx, int sy)
{
	int i;
	gdImagePtr im;

	if (overflow2(sx, sy)) {
		return NULL;
	}
	if (overflow2(sizeof (unsigned char *), sy)) {
		return NULL;
	}
	if (overflow2(sizeof (unsigned char), sx)) {
		return NULL;
	}

	im = (gdImage *) gdCalloc(1, sizeof(gdImage));
	if (!im) {
		return NULL;
	}

	/* Row-major ever since gd 1.3 */
	im->pixels = (unsigned char **) gdMalloc (sizeof (unsigned char *) * sy);
	if (!im->pixels) {
		gdFree(im);
		return NULL;
	}

	im->polyInts = 0;
	im->polyAllocated = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,6 +188,7 @@
 	if (overflow2(sx, sy)) {
 		return NULL;
 	}
+
 	if (overflow2(sizeof (unsigned char *), sy)) {
 		return NULL;
 	}
```
