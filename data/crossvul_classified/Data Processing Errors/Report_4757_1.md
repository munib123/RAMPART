# CrossVul Fix Pair: Data Processing Errors in java
**Pair ID:** 4757_1
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4757_1`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```java
Lines 592-633 of the vulnerable file.

            w = (int)zz_1;
            zz[1] = (w << 1) | c;
            c = w >>> 31;
            zz_2 += zz_1 >>> 32;
        }

        long x_2 = x[2] & M;
        long zz_3 = zz[3] & M;
        long zz_4 = zz[4] & M;
        {
            zz_2 += x_2 * x_0;
            w = (int)zz_2;
            zz[2] = (w << 1) | c;
            c = w >>> 31;
            zz_3 += (zz_2 >>> 32) + x_2 * x_1;
            zz_4 += zz_3 >>> 32;
            zz_3 &= M;
        }

        long x_3 = x[3] & M;
        long zz_5 = zz[5] & M;
        long zz_6 = zz[6] & M;
        {
            zz_3 += x_3 * x_0;
            w = (int)zz_3;
            zz[3] = (w << 1) | c;
            c = w >>> 31;
            zz_4 += (zz_3 >>> 32) + x_3 * x_1;
            zz_5 += (zz_4 >>> 32) + x_3 * x_2;
            zz_4 &= M;
            zz_6 += zz_5 >>> 32;
            zz_5 &= M;
        }

        long x_4 = x[4] & M;
        long zz_7 = zz[7] & M;
        long zz_8 = zz[8] & M;
        {
            zz_4 += x_4 * x_0;
            w = (int)zz_4;
            zz[4] = (w << 1) | c;
            c = w >>> 31;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -609,8 +609,8 @@
         }
 
         long x_3 = x[3] & M;
-        long zz_5 = zz[5] & M;
-        long zz_6 = zz[6] & M;
+        long zz_5 = (zz[5] & M) + (zz_4 >>> 32); zz_4 &= M;
+        long zz_6 = (zz[6] & M) + (zz_5 >>> 32); zz_5 &= M;
         {
             zz_3 += x_3 * x_0;
             w = (int)zz_3;
@@ -624,8 +624,8 @@
         }
 
         long x_4 = x[4] & M;
-        long zz_7 = zz[7] & M;
-        long zz_8 = zz[8] & M;
+        long zz_7 = (zz[7] & M) + (zz_6 >>> 32); zz_6 &= M;
+        long zz_8 = (zz[8] & M) + (zz_7 >>> 32); zz_7 &= M;
         {
             zz_4 += x_4 * x_0;
             w = (int)zz_4;
@@ -649,7 +649,7 @@
         w = (int)zz_8;
         zz[8] = (w << 1) | c;
         c = w >>> 31;
-        w = zz[9] + (int)(zz_8 >> 32);
+        w = zz[9] + (int)(zz_8 >>> 32);
         zz[9] = (w << 1) | c;
     }
 
@@ -704,8 +704,8 @@
         }
 
         long x_3 = x[xOff + 3] & M;
-        long zz_5 = zz[zzOff + 5] & M;
-        long zz_6 = zz[zzOff + 6] & M;
+        long zz_5 = (zz[zzOff + 5] & M) + (zz_4 >>> 32); zz_4 &= M;
+        long zz_6 = (zz[zzOff + 6] & M) + (zz_5 >>> 32); zz_5 &= M;
         {
             zz_3 += x_3 * x_0;
             w = (int)zz_3;
@@ -719,8 +719,8 @@
         }
 
         long x_4 = x[xOff + 4] & M;
-        long zz_7 = zz[zzOff + 7] & M;
-        long zz_8 = zz[zzOff + 8] & M;
+        long zz_7 = (zz[zzOff + 7] & M) + (zz_6 >>> 32); zz_6 &= M;
+        long zz_8 = (zz[zzOff + 8] & M) + (zz_7 >>> 32); zz_7 &= M;
         {
             zz_4 += x_4 * x_0;
             w = (int)zz_4;
@@ -744,7 +744,7 @@
         w = (int)zz_8;
         zz[zzOff + 8] = (w << 1) | c;
         c = w >>> 31;
-        w = zz[zzOff + 9] + (int)(zz_8 >> 32);
+        w = zz[zzOff + 9] + (int)(zz_8 >>> 32);
         zz[zzOff + 9] = (w << 1) | c;
     }
 
```
