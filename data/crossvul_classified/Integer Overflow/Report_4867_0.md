# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4867_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4867_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 658-698 of the vulnerable file.

		if (palette_len > 0U) {
			OPJ_UINT8 has_color = 0U;
			for (i = 0U; i < palette_len; i++) {
				lut_B[i] = (OPJ_UINT8)getc(IN);
				lut_G[i] = (OPJ_UINT8)getc(IN);
				lut_R[i] = (OPJ_UINT8)getc(IN);
				(void)getc(IN); /* padding */
				has_color |= (lut_B[i] ^ lut_G[i]) | (lut_G[i] ^ lut_R[i]);
			}
			if(has_color) {
				numcmpts = 3U;
			}
		}
	} else {
		numcmpts = 3U;
		if ((Info_h.biCompression == 3) && (Info_h.biAlphaMask != 0U)) {
			numcmpts++;
		}
	}
	
	stride = ((Info_h.biWidth * Info_h.biBitCount + 31U) / 32U) * 4U; /* rows are aligned on 32bits */
	if (Info_h.biBitCount == 4 && Info_h.biCompression == 2) { /* RLE 4 gets decoded as 8 bits data for now... */
		stride = ((Info_h.biWidth * 8U + 31U) / 32U) * 4U;
	}
	pData = (OPJ_UINT8 *) calloc(1, stride * Info_h.biHeight * sizeof(OPJ_UINT8));
	if (pData == NULL) {
		fclose(IN);
		return NULL;
	}
	/* Place the cursor at the beginning of the image information */
	fseek(IN, 0, SEEK_SET);
	fseek(IN, (long)File_h.bfOffBits, SEEK_SET);
	
	switch (Info_h.biCompression) {
		case 0:
		case 3:
			/* read raw data */
			l_result = bmp_read_raw_data(IN, pData, stride, Info_h.biWidth, Info_h.biHeight);
			break;
		case 1:
			/* read rle8 data */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -675,9 +675,27 @@
 		}
 	}
 	
+	if (Info_h.biWidth == 0 || Info_h.biHeight == 0) {
+		fclose(IN);
+		return NULL;
+	}
+	
+	if (Info_h.biBitCount > (((OPJ_UINT32)-1) - 31) / Info_h.biWidth) {
+		fclose(IN);
+		return NULL;
+	}
 	stride = ((Info_h.biWidth * Info_h.biBitCount + 31U) / 32U) * 4U; /* rows are aligned on 32bits */
 	if (Info_h.biBitCount == 4 && Info_h.biCompression == 2) { /* RLE 4 gets decoded as 8 bits data for now... */
+		if (8 > (((OPJ_UINT32)-1) - 31) / Info_h.biWidth) {
+			fclose(IN);
+			return NULL;
+		}
 		stride = ((Info_h.biWidth * 8U + 31U) / 32U) * 4U;
+	}
+	
+	if (stride > ((OPJ_UINT32)-1) / sizeof(OPJ_UINT8) / Info_h.biHeight) {
+		fclose(IN);
+		return NULL;
 	}
 	pData = (OPJ_UINT8 *) calloc(1, stride * Info_h.biHeight * sizeof(OPJ_UINT8));
 	if (pData == NULL) {
```
