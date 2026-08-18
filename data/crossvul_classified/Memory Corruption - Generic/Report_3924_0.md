# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3924_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3924_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1380-1420 of the vulnerable file.

	WLog_INFO(TAG, "\tpad2OctetsA: 0x%04" PRIX16 "", pad2OctetsA);
	WLog_INFO(TAG, "\tkeyboardLayout: 0x%08" PRIX32 "", keyboardLayout);
	WLog_INFO(TAG, "\tkeyboardType: 0x%08" PRIX32 "", keyboardType);
	WLog_INFO(TAG, "\tkeyboardSubType: 0x%08" PRIX32 "", keyboardSubType);
	WLog_INFO(TAG, "\tkeyboardFunctionKey: 0x%08" PRIX32 "", keyboardFunctionKey);
	return TRUE;
}
#endif

/**
 * Read font capability set.\n
 * @msdn{cc240571}
 * @param s stream
 * @param settings settings
 * @return if the operation completed successfully
 */

static BOOL rdp_read_font_capability_set(wStream* s, UINT16 length, rdpSettings* settings)
{
	WINPR_UNUSED(settings);
	if (length > 4)
		Stream_Seek_UINT16(s); /* fontSupportFlags (2 bytes) */

	if (length > 6)
		Stream_Seek_UINT16(s); /* pad2Octets (2 bytes) */

	return TRUE;
}

/**
 * Write font capability set.\n
 * @msdn{cc240571}
 * @param s stream
 * @param settings settings
 */

static BOOL rdp_write_font_capability_set(wStream* s, const rdpSettings* settings)
{
	size_t header;

	WINPR_UNUSED(settings);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1397,10 +1397,10 @@
 static BOOL rdp_read_font_capability_set(wStream* s, UINT16 length, rdpSettings* settings)
 {
 	WINPR_UNUSED(settings);
-	if (length > 4)
+	if (length > 5)
 		Stream_Seek_UINT16(s); /* fontSupportFlags (2 bytes) */
 
-	if (length > 6)
+	if (length > 7)
 		Stream_Seek_UINT16(s); /* pad2Octets (2 bytes) */
 
 	return TRUE;
```
