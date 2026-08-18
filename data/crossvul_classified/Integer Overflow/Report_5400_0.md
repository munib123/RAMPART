# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5400_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5400_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 118-137 of the vulnerable file.

}

/* Dump memory to a stream. */
int jas_memdump(FILE *out, void *data, size_t len)
{
	size_t i;
	size_t j;
	uchar *dp;
	dp = data;
	for (i = 0; i < len; i += 16) {
		fprintf(out, "%04zx:", i);
		for (j = 0; j < 16; ++j) {
			if (i + j < len) {
				fprintf(out, " %02x", dp[i + j]);
			}
		}
		fprintf(out, "\n");
	}
	return 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -135,3 +135,22 @@
 	}
 	return 0;
 }
+
+/******************************************************************************\
+* Code.
+\******************************************************************************/
+
+void jas_deprecated(const char *s)
+{
+	static char message[] =
+	"WARNING!!! WARNING!!! WARNING!!! WARNING!!! WARNING!!! WARNING!!!\n"
+	"WARNING!!! WARNING!!! WARNING!!! WARNING!!! WARNING!!! WARNING!!!\n"
+	"WARNING!!! WARNING!!! WARNING!!! WARNING!!! WARNING!!! WARNING!!!\n"
+	"YOUR CODE IS RELYING ON DEPRECATED FUNCTIONALTIY IN THE JASPER LIBRARY.\n"
+	"THIS FUNCTIONALITY WILL BE REMOVED IN THE NEAR FUTURE.\n"
+	"PLEASE FIX THIS PROBLEM BEFORE YOUR CODE STOPS WORKING!\n"
+	;
+	jas_eprintf("%s", message);
+	jas_eprintf("The specific problem is as follows:\n%s\n", s);
+	//abort();
+}
```
