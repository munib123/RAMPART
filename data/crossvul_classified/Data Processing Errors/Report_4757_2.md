# CrossVul Fix Pair: Data Processing Errors in java
**Pair ID:** 4757_2
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4757_2`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```java
Lines 698-739 of the vulnerable file.

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
@@ -715,8 +715,8 @@
         }
 
         long x_3 = x[3] & M;
-        long zz_5 = zz[5] & M;
-        long zz_6 = zz[6] & M;
+        long zz_5 = (zz[5] & M) + (zz_4 >>> 32); zz_4 &= M;
+        long zz_6 = (zz[6] & M) + (zz_5 >>> 32); zz_5 &= M;
         {
             zz_3 += x_3 * x_0;
             w = (int)zz_3;
@@ -730,8 +730,8 @@
         }
 
         long x_4 = x[4] & M;
-        long zz_7 = zz[7] & M;
-        long zz_8 = zz[8] & M;
+        long zz_7 = (zz[7] & M) + (zz_6 >>> 32); zz_6 &= M;
+        long zz_8 = (zz[8] & M) + (zz_7 >>> 32); zz_7 &= M;
         {
             zz_4 += x_4 * x_0;
             w = (int)zz_4;
@@ -747,8 +747,8 @@
         }
 
         long x_5 = x[5] & M;
-        long zz_9 = zz[9] & M;
-        long zz_10 = zz[10] & M;
+        long zz_9 = (zz[9] & M) + (zz_8 >>> 32); zz_8 &= M;
+        long zz_10 = (zz[10] & M) + (zz_9 >>> 32); zz_9 &= M;
         {
             zz_5 += x_5 * x_0;
             w = (int)zz_5;
@@ -776,7 +776,7 @@
         w = (int)zz_10;
         zz[10] = (w << 1) | c;
         c = w >>> 31;
-        w = zz[11] + (int)(zz_10 >> 32);
+        w = zz[11] + (int)(zz_10 >>> 32);
         zz[11] = (w << 1) | c;
     }
 
@@ -831,8 +831,8 @@
         }
 
         long x_3 = x[xOff + 3] & M;
-        long zz_5 = zz[zzOff + 5] & M;
-        long zz_6 = zz[zzOff + 6] & M;
+        long zz_5 = (zz[zzOff + 5] & M) + (zz_4 >>> 32); zz_4 &= M;
+        long zz_6 = (zz[zzOff + 6] & M) + (zz_5 >>> 32); zz_5 &= M;
         {
             zz_3 += x_3 * x_0;
             w = (int)zz_3;
@@ -846,8 +846,8 @@
         }
 
         long x_4 = x[xOff + 4] & M;
-        long zz_7 = zz[zzOff + 7] & M;
-        long zz_8 = zz[zzOff + 8] & M;
+        long zz_7 = (zz[zzOff + 7] & M) + (zz_6 >>> 32); zz_6 &= M;
+        long zz_8 = (zz[zzOff + 8] & M) + (zz_7 >>> 32); zz_7 &= M;
         {
             zz_4 += x_4 * x_0;
             w = (int)zz_4;
@@ -863,8 +863,8 @@
         }
 
         long x_5 = x[xOff + 5] & M;
-        long zz_9 = zz[zzOff + 9] & M;
-        long zz_10 = zz[zzOff + 10] & M;
+        long zz_9 = (zz[zzOff + 9] & M) + (zz_8 >>> 32); zz_8 &= M;
+        long zz_10 = (zz[zzOff + 10] & M) + (zz_9 >>> 32); zz_9 &= M;
         {
             zz_5 += x_5 * x_0;
             w = (int)zz_5;
@@ -892,7 +892,7 @@
         w = (int)zz_10;
         zz[zzOff + 10] = (w << 1) | c;
         c = w >>> 31;
-        w = zz[zzOff + 11] + (int)(zz_10 >> 32);
+        w = zz[zzOff + 11] + (int)(zz_10 >>> 32);
         zz[zzOff + 11] = (w << 1) | c;
     }
 
```
