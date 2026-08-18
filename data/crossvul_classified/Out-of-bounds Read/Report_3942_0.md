# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3942_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3942_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 383-423 of the vulnerable file.

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_ERR(TAG, "not enough remaining data");
		return ERROR_INVALID_DATA;
	}

	Stream_Read_UINT32(s, response->streamId);   /* streamId (4 bytes) */
	response->requestedData = Stream_Pointer(s); /* requestedFileContentsData */
	response->cbRequested = response->dataLen - 4;
	return CHANNEL_RC_OK;
}

UINT cliprdr_read_format_list(wStream* s, CLIPRDR_FORMAT_LIST* formatList, BOOL useLongFormatNames)
{
	UINT32 index;
	size_t position;
	BOOL asciiNames;
	int formatNameLength;
	char* szFormatName;
	WCHAR* wszFormatName;
	UINT32 dataLen = formatList->dataLen;
	CLIPRDR_FORMAT* formats = NULL;
	UINT error = CHANNEL_RC_OK;

	asciiNames = (formatList->msgFlags & CB_ASCII_NAMES) ? TRUE : FALSE;

	index = 0;
	formatList->numFormats = 0;
	position = Stream_GetPosition(s);

	if (!formatList->dataLen)
	{
		/* empty format list */
		formatList->formats = NULL;
		formatList->numFormats = 0;
	}
	else if (!useLongFormatNames)
	{
		formatList->numFormats = (dataLen / 36);

		if ((formatList->numFormats * 36) != dataLen)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -400,29 +400,32 @@
 	int formatNameLength;
 	char* szFormatName;
 	WCHAR* wszFormatName;
-	UINT32 dataLen = formatList->dataLen;
+	wStream sub1, sub2;
 	CLIPRDR_FORMAT* formats = NULL;
 	UINT error = CHANNEL_RC_OK;
 
 	asciiNames = (formatList->msgFlags & CB_ASCII_NAMES) ? TRUE : FALSE;
 
 	index = 0;
+	/* empty format list */
+	formatList->formats = NULL;
 	formatList->numFormats = 0;
-	position = Stream_GetPosition(s);
+
+	Stream_StaticInit(&sub1, Stream_Pointer(s), formatList->dataLen);
+	if (!Stream_SafeSeek(s, formatList->dataLen))
+		return ERROR_INVALID_DATA;
 
 	if (!formatList->dataLen)
 	{
-		/* empty format list */
-		formatList->formats = NULL;
-		formatList->numFormats = 0;
 	}
 	else if (!useLongFormatNames)
 	{
-		formatList->numFormats = (dataLen / 36);
-
-		if ((formatList->numFormats * 36) != dataLen)
-		{
-			WLog_ERR(TAG, "Invalid short format list length: %" PRIu32 "", dataLen);
+		const size_t cap = Stream_Capacity(&sub1);
+		formatList->numFormats = (cap / 36);
+
+		if ((formatList->numFormats * 36) != cap)
+		{
+			WLog_ERR(TAG, "Invalid short format list length: %" PRIuz "", cap);
 			return ERROR_INTERNAL_ERROR;
 		}
 
@@ -437,10 +440,9 @@
 
 		formatList->formats = formats;
 
-		while (dataLen)
-		{
-			Stream_Read_UINT32(s, formats[index].formatId); /* formatId (4 bytes) */
-			dataLen -= 4;
+		while (Stream_GetRemainingLength(&sub1) >= 4)
+		{
+			Stream_Read_UINT32(&sub1, formats[index].formatId); /* formatId (4 bytes) */
 
 			formats[index].formatName = NULL;
 
@@ -452,10 +454,12 @@
 			 * These are 16 unicode charaters - *without* terminating null !
 			 */
 
+			szFormatName = (char*)Stream_Pointer(&sub1);
+			wszFormatName = (WCHAR*)Stream_Pointer(&sub1);
+			if (!Stream_SafeSeek(&sub1, 32))
+				goto error_out;
 			if (asciiNames)
 			{
-				szFormatName = (char*)Stream_Pointer(s);
-
 				if (szFormatName[0])
 				{
 					/* ensure null termination */
@@ -472,8 +476,6 @@
 			}
 			else
 			{
-				wszFormatName = (WCHAR*)Stream_Pointer(s);
-
 				if (wszFormatName[0])
 				{
 					/* ConvertFromUnicode always returns a null-terminated
@@ -489,33 +491,26 @@
 				}
 			}
 
-			Stream_Seek(s, 32);
-			dataLen -= 32;
 			index++;
 		}
 	}
 	else
 	{
-		while (dataLen)
-		{
-			Stream_Seek(s, 4); /* formatId (4 bytes) */
-			dataLen -= 4;
-
-			wszFormatName = (WCHAR*)Stream_Pointer(s);
-
-			if (!wszFormatName[0])
-				formatNameLength = 0;
-			else
-				formatNameLength = _wcslen(wszFormatName);
-
-			Stream_Seek(s, (formatNameLength + 1) * 2);
-			dataLen -= ((formatNameLength + 1) * 2);
-
+		sub2 = sub1;
+		while (Stream_GetRemainingLength(&sub1) > 0)
+		{
+			size_t rest;
+			if (!Stream_SafeSeek(&sub1, 4)) /* formatId (4 bytes) */
+				goto error_out;
+
+			wszFormatName = (WCHAR*)Stream_Pointer(&sub1);
+			rest = Stream_GetRemainingLength(&sub1);
+			formatNameLength = _wcsnlen(wszFormatName, rest / sizeof(WCHAR));
+
+			if (!Stream_SafeSeek(&sub1, (formatNameLength + 1) * sizeof(WCHAR)))
+				goto error_out;
 			formatList->numFormats++;
 		}
-
-		dataLen = formatList->dataLen;
-		Stream_SetPosition(s, position);
 
 		if (formatList->numFormats)
 			formats = (CLIPRDR_FORMAT*)calloc(formatList->numFormats, sizeof(CLIPRDR_FORMAT));
@@ -528,24 +523,23 @@
 
 		formatList->formats = formats;
 
-		while (dataLen)
-		{
-			Stream_Read_UINT32(s, formats[index].formatId); /* formatId (4 bytes) */
-			dataLen -= 4;
+		while (Stream_GetRemainingLength(&sub2) >= 4)
+		{
+			size_t rest;
+			Stream_Read_UINT32(&sub2, formats[index].formatId); /* formatId (4 bytes) */
 
 			formats[index].formatName = NULL;
 
-			wszFormatName = (WCHAR*)Stream_Pointer(s);
-
-			if (!wszFormatName[0])
-				formatNameLength = 0;
-			else
-				formatNameLength = _wcslen(wszFormatName);
+			wszFormatName = (WCHAR*)Stream_Pointer(&sub2);
+			rest = Stream_GetRemainingLength(&sub2);
+			formatNameLength = _wcsnlen(wszFormatName, rest / sizeof(WCHAR));
+			if (!Stream_SafeSeek(&sub2, (formatNameLength + 1) * sizeof(WCHAR)))
+				goto error_out;
 
 			if (formatNameLength)
 			{
-				if (ConvertFromUnicode(CP_UTF8, 0, wszFormatName, -1, &(formats[index].formatName),
-				                       0, NULL, NULL) < 1)
+				if (ConvertFromUnicode(CP_UTF8, 0, wszFormatName, formatNameLength,
+				                       &(formats[index].formatName), 0, NULL, NULL) < 1)
 				{
 					WLog_ERR(TAG, "failed to convert long clipboard format name");
 					error = ERROR_INTERNAL_ERROR;
@@ -553,9 +547,6 @@
 				}
 			}
 
-			Stream_Seek(s, (formatNameLength + 1) * 2);
-			dataLen -= ((formatNameLength + 1) * 2);
-
 			index++;
 		}
 	}
@@ -582,5 +573,7 @@
 		}
 
 		free(formatList->formats);
-	}
-}
+		formatList->formats = NULL;
+		formatList->numFormats = 0;
+	}
+}
```
