# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 763_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `763_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 290-331 of the vulnerable file.

				free(output);
				free(input);
				return MYSOFA_INVALID_FORMAT;
			}

			olen = elements * size;
			err = gunzip(size_of_chunk, input, &olen, output);
			free(input);

			log("   gunzip %d %d %d\n",err, olen, elements*size);
			if (err || olen != elements * size) {
				free(output);
				return MYSOFA_INVALID_FORMAT;
			}

			switch (data->ds.dimensionality) {
			case 1:
				for (i = 0; i < olen; i++) {
					b = i / elements;
					x = i % elements + start[0];
					if (x < sx) {
						j = x * size + b;
						((char*)data->data)[j] = output[i];
					}
				}
				break;
			case 2:
				for (i = 0; i < olen; i++) {
					b = i / elements;
					x = i % elements;
					y = x % dy + start[1];
					x = x / dy + start[0];
					if (y < sy && x < sx) {
						j = ((x * sy + y) * size) + b;
						((char*)data->data)[j] = output[i];
					}
				}
				break;
			case 3:
				for (i = 0; i < olen; i++) {
					b = i / elements;
					x = i % elements;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -307,8 +307,8 @@
 				for (i = 0; i < olen; i++) {
 					b = i / elements;
 					x = i % elements + start[0];
-					if (x < sx) {
-						j = x * size + b;
+					j = x * size + b;
+					if (j>=0 && j < elements * size) {
 						((char*)data->data)[j] = output[i];
 					}
 				}
@@ -319,8 +319,8 @@
 					x = i % elements;
 					y = x % dy + start[1];
 					x = x / dy + start[0];
-					if (y < sy && x < sx) {
-						j = ((x * sy + y) * size) + b;
+					j = ((x * sy + y) * size) + b;
+					if (j>=0 && j < elements * size) {
 						((char*)data->data)[j] = output[i];
 					}
 				}
@@ -332,8 +332,8 @@
 					z = x % dz + start[2];
 					y = (x / dz) % dy + start[1];
 					x = (x / dzy) + start[0];
-					if (z < sz && y < sy && x < sx) {
-						j = (x * szy + y * sz + z) * size + b;
+					j = (x * szy + y * sz + z) * size + b;
+					if (j>=0 && j < elements * size) {
 						((char*)data->data)[j] = output[i];
 					}
 				}
```
