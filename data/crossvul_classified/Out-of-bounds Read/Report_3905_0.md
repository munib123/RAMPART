# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3905_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3905_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 119-161 of the vulnerable file.

		case 1:
		case 4:
		case 8:
			if (Stream_GetRemainingLength(s) < 2)
				return FALSE;

			Stream_Read_UINT16(s, iconInfo->cbColorTable); /* cbColorTable (2 bytes) */
			break;

		default:
			iconInfo->cbColorTable = 0;
			break;
	}

	if (Stream_GetRemainingLength(s) < 4)
		return FALSE;

	Stream_Read_UINT16(s, iconInfo->cbBitsMask);  /* cbBitsMask (2 bytes) */
	Stream_Read_UINT16(s, iconInfo->cbBitsColor); /* cbBitsColor (2 bytes) */

	if (Stream_GetRemainingLength(s) < iconInfo->cbBitsMask + iconInfo->cbBitsColor)
		return FALSE;

	/* bitsMask */
	newBitMask = (BYTE*)realloc(iconInfo->bitsMask, iconInfo->cbBitsMask);

	if (!newBitMask)
	{
		free(iconInfo->bitsMask);
		iconInfo->bitsMask = NULL;
		return FALSE;
	}

	iconInfo->bitsMask = newBitMask;
	Stream_Read(s, iconInfo->bitsMask, iconInfo->cbBitsMask);

	/* colorTable */
	if (iconInfo->colorTable == NULL)
	{
		if (iconInfo->cbColorTable)
		{
			iconInfo->colorTable = (BYTE*)malloc(iconInfo->cbColorTable);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,9 +136,6 @@
 	Stream_Read_UINT16(s, iconInfo->cbBitsMask);  /* cbBitsMask (2 bytes) */
 	Stream_Read_UINT16(s, iconInfo->cbBitsColor); /* cbBitsColor (2 bytes) */
 
-	if (Stream_GetRemainingLength(s) < iconInfo->cbBitsMask + iconInfo->cbBitsColor)
-		return FALSE;
-
 	/* bitsMask */
 	newBitMask = (BYTE*)realloc(iconInfo->bitsMask, iconInfo->cbBitsMask);
 
@@ -150,6 +147,8 @@
 	}
 
 	iconInfo->bitsMask = newBitMask;
+	if (Stream_GetRemainingLength(s) < iconInfo->cbBitsMask)
+		return FALSE;
 	Stream_Read(s, iconInfo->bitsMask, iconInfo->cbBitsMask);
 
 	/* colorTable */
@@ -184,7 +183,11 @@
 	}
 
 	if (iconInfo->colorTable)
+	{
+		if (Stream_GetRemainingLength(s) < iconInfo->cbColorTable)
+			return FALSE;
 		Stream_Read(s, iconInfo->colorTable, iconInfo->cbColorTable);
+	}
 
 	/* bitsColor */
 	newBitMask = (BYTE*)realloc(iconInfo->bitsColor, iconInfo->cbBitsColor);
@@ -197,6 +200,8 @@
 	}
 
 	iconInfo->bitsColor = newBitMask;
+	if (Stream_GetRemainingLength(s) < iconInfo->cbBitsColor)
+		return FALSE;
 	Stream_Read(s, iconInfo->bitsColor, iconInfo->cbBitsColor);
 	return TRUE;
 }
```
