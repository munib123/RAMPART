# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4062_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4062_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 193-233 of the vulnerable file.


     /* for each *destination* pixel... */
     for (y = 0; y < h1; y++) {
       for (x = 0; x < w1; x++) {
         red = green = blue = 0;
         /* Get the totals for rgb from the source grid... */
         for (w = 0; w < areaX; w++) {
           for (v = 0; v < areaY; v++) {
             srcptr2 = &srcptr[(((x * areaX) + w) * bytesPerPixel) +
                               (v * screen->paddedWidthInBytes)];
             pixel_value = 0;


             switch (bytesPerPixel) {
             case 4: pixel_value = *((unsigned int *)srcptr2);   break;
             case 2: pixel_value = *((unsigned short *)srcptr2); break;
             case 1: pixel_value = *((unsigned char *)srcptr2);  break;
             default:
               /* fixme: endianness problem? */
               for (z = 0; z < bytesPerPixel; z++)
                 pixel_value += (srcptr2[z] << (8 * z));
                break;
              }
              /*
              srcptr2 += bytesPerPixel;
              */

            red += ((pixel_value >> redShift) & redMax);
            green += ((pixel_value >> greenShift) & greenMax);
            blue += ((pixel_value >> blueShift) & blueMax);

           }
         }
         /* We now have a total for all of the colors, find the average! */
         red /= area2;
         green /= area2;
         blue /= area2;
          /* Stuff the new value back into memory */
         pixel_value = ((red & redMax) << redShift) | ((green & greenMax) << greenShift) | ((blue & blueMax) << blueShift);

         switch (bytesPerPixel) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -210,7 +210,7 @@
              default:
                /* fixme: endianness problem? */
                for (z = 0; z < bytesPerPixel; z++)
-                 pixel_value += (srcptr2[z] << (8 * z));
+                 pixel_value += ((unsigned long)srcptr2[z] << (8 * z));
                 break;
               }
               /*
```
