# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5474_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5474_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 966-1016 of the vulnerable file.

		r1 = (int32) CLAMP(ip[0]); wp[0] = (uint16)((r1-r2) & mask); r2 = r1;
		g1 = (int32) CLAMP(ip[1]); wp[1] = (uint16)((g1-g2) & mask); g2 = g1;
		b1 = (int32) CLAMP(ip[2]); wp[2] = (uint16)((b1-b2) & mask); b2 = b1;
	    }
	} else if (stride == 4) {
	    r2 = wp[0] = (uint16) CLAMP(ip[0]);
	    g2 = wp[1] = (uint16) CLAMP(ip[1]);
	    b2 = wp[2] = (uint16) CLAMP(ip[2]);
	    a2 = wp[3] = (uint16) CLAMP(ip[3]);
	    n -= 4;
	    while (n > 0) {
		n -= 4;
		wp += 4;
		ip += 4;
		r1 = (int32) CLAMP(ip[0]); wp[0] = (uint16)((r1-r2) & mask); r2 = r1;
		g1 = (int32) CLAMP(ip[1]); wp[1] = (uint16)((g1-g2) & mask); g2 = g1;
		b1 = (int32) CLAMP(ip[2]); wp[2] = (uint16)((b1-b2) & mask); b2 = b1;
		a1 = (int32) CLAMP(ip[3]); wp[3] = (uint16)((a1-a2) & mask); a2 = a1;
	    }
	} else {
	    ip += n - 1;	/* point to last one */
	    wp += n - 1;	/* point to last one */
	    n -= stride;
	    while (n > 0) {
		REPEAT(stride, wp[0] = (uint16) CLAMP(ip[0]);
				wp[stride] -= wp[0];
				wp[stride] &= mask;
				wp--; ip--)
		n -= stride;
	    }
	    REPEAT(stride, wp[0] = (uint16) CLAMP(ip[0]); wp--; ip--)
	}
    }
}

static void
horizontalDifference16(unsigned short *ip, int n, int stride, 
	unsigned short *wp, uint16 *From14)
{
    register int  r1, g1, b1, a1, r2, g2, b2, a2, mask;

/* assumption is unsigned pixel values */
#undef   CLAMP
#define  CLAMP(v) From14[(v) >> 2]

    mask = CODE_MASK;
    if (n >= stride) {
	if (stride == 3) {
	    r2 = wp[0] = CLAMP(ip[0]);  g2 = wp[1] = CLAMP(ip[1]);
	    b2 = wp[2] = CLAMP(ip[2]);
	    n -= 3;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -983,17 +983,14 @@
 		a1 = (int32) CLAMP(ip[3]); wp[3] = (uint16)((a1-a2) & mask); a2 = a1;
 	    }
 	} else {
-	    ip += n - 1;	/* point to last one */
-	    wp += n - 1;	/* point to last one */
-	    n -= stride;
-	    while (n > 0) {
-		REPEAT(stride, wp[0] = (uint16) CLAMP(ip[0]);
-				wp[stride] -= wp[0];
-				wp[stride] &= mask;
-				wp--; ip--)
-		n -= stride;
-	    }
-	    REPEAT(stride, wp[0] = (uint16) CLAMP(ip[0]); wp--; ip--)
+        REPEAT(stride, wp[0] = (uint16) CLAMP(ip[0]); wp++; ip++)
+        n -= stride;
+        while (n > 0) {
+            REPEAT(stride,
+                wp[0] = (uint16)(((int32)CLAMP(ip[0])-(int32)CLAMP(ip[-stride])) & mask);
+                wp++; ip++)
+            n -= stride;
+        }
 	}
     }
 }
@@ -1036,17 +1033,14 @@
 		a1 = CLAMP(ip[3]); wp[3] = (uint16)((a1-a2) & mask); a2 = a1;
 	    }
 	} else {
-	    ip += n - 1;	/* point to last one */
-	    wp += n - 1;	/* point to last one */
+        REPEAT(stride, wp[0] = CLAMP(ip[0]); wp++; ip++)
 	    n -= stride;
 	    while (n > 0) {
-		REPEAT(stride, wp[0] = CLAMP(ip[0]);
-				wp[stride] -= wp[0];
-				wp[stride] &= mask;
-				wp--; ip--)
-		n -= stride;
-	    }
-	    REPEAT(stride, wp[0] = CLAMP(ip[0]); wp--; ip--)
+            REPEAT(stride,
+                wp[0] = (uint16)((CLAMP(ip[0])-CLAMP(ip[-stride])) & mask);
+                wp++; ip++)
+            n -= stride;
+        }
 	}
     }
 }
@@ -1089,18 +1083,15 @@
 		ip += 4;
 	    }
 	} else {
-	    wp += n + stride - 1;	/* point to last one */
-	    ip += n + stride - 1;	/* point to last one */
-	    n -= stride;
-	    while (n > 0) {
-		REPEAT(stride, wp[0] = CLAMP(ip[0]);
-				wp[stride] -= wp[0];
-				wp[stride] &= mask;
-				wp--; ip--)
-		n -= stride;
-	    }
-	    REPEAT(stride, wp[0] = CLAMP(ip[0]); wp--; ip--)
-	}
+        REPEAT(stride, wp[0] = CLAMP(ip[0]); wp++; ip++)
+        n -= stride;
+        while (n > 0) {
+            REPEAT(stride,
+                wp[0] = (uint16)((CLAMP(ip[0])-CLAMP(ip[-stride])) & mask);
+                wp++; ip++)
+            n -= stride;
+        }
+    }
     }
 }
 
```
