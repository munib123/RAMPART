# CrossVul Fix Pair: Incorrect Conversion between Numeric Types in c
**Pair ID:** 4495_0
**Vulnerability Class:** Incorrect Conversion between Numeric Types
**CWE:** CWE-681
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4495_0`)

## Vulnerability Information & PoC

## Description
Incorrect Conversion between Numeric Types - When converting from one data type to another, such as long to integer, data can be omitted or translated in a way that produces unexpected values.

## Vulnerable Code
```c
Lines 3745-3785 of the vulnerable file.

			break;

		default:
			WLog_Print(update->log, WLOG_WARN, "SECONDARY ORDER %s not supported", name);
			break;
	}

	if (!rc)
	{
		WLog_Print(update->log, WLOG_ERROR, "SECONDARY ORDER %s failed", name);
	}

	start += orderLength + 7;
	end = Stream_GetPosition(s);
	if (start > end)
	{
		WLog_Print(update->log, WLOG_WARN, "SECONDARY_ORDER %s: read %" PRIuz "bytes too much",
		           name, end - start);
		return FALSE;
	}
	diff = start - end;
	if (diff > 0)
	{
		WLog_Print(update->log, WLOG_DEBUG,
		           "SECONDARY_ORDER %s: read %" PRIuz "bytes short, skipping", name, diff);
		Stream_Seek(s, diff);
	}
	return rc;
}

static BOOL read_altsec_order(wStream* s, BYTE orderType, rdpAltSecUpdate* altsec)
{
	BOOL rc = FALSE;

	switch (orderType)
	{
		case ORDER_TYPE_CREATE_OFFSCREEN_BITMAP:
			rc = update_read_create_offscreen_bitmap_order(s, &(altsec->create_offscreen_bitmap));
			break;

		case ORDER_TYPE_SWITCH_SURFACE:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3762,12 +3762,13 @@
 		           name, end - start);
 		return FALSE;
 	}
-	diff = start - end;
+	diff = end - start;
 	if (diff > 0)
 	{
 		WLog_Print(update->log, WLOG_DEBUG,
 		           "SECONDARY_ORDER %s: read %" PRIuz "bytes short, skipping", name, diff);
-		Stream_Seek(s, diff);
+		if (!Stream_SafeSeek(s, diff))
+			return FALSE;
 	}
 	return rc;
 }
```
