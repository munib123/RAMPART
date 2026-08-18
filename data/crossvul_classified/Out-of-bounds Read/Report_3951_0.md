# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3951_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3951_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 26-85 of the vulnerable file.

#include "window.h"

#include <winpr/wtypes.h>
#include <winpr/crt.h>

#include <freerdp/api.h>
#include <freerdp/log.h>
#include <freerdp/graphics.h>
#include <freerdp/codec/bitmap.h>
#include <freerdp/gdi/gdi.h>

#include "orders.h"

#include "../cache/glyph.h"
#include "../cache/bitmap.h"
#include "../cache/brush.h"
#include "../cache/cache.h"

#define TAG FREERDP_TAG("core.orders")

const BYTE PRIMARY_DRAWING_ORDER_FIELD_BYTES[] = { DSTBLT_ORDER_FIELD_BYTES,
	                                               PATBLT_ORDER_FIELD_BYTES,
	                                               SCRBLT_ORDER_FIELD_BYTES,
	                                               0,
	                                               0,
	                                               0,
	                                               0,
	                                               DRAW_NINE_GRID_ORDER_FIELD_BYTES,
	                                               MULTI_DRAW_NINE_GRID_ORDER_FIELD_BYTES,
	                                               LINE_TO_ORDER_FIELD_BYTES,
	                                               OPAQUE_RECT_ORDER_FIELD_BYTES,
	                                               SAVE_BITMAP_ORDER_FIELD_BYTES,
	                                               0,
	                                               MEMBLT_ORDER_FIELD_BYTES,
	                                               MEM3BLT_ORDER_FIELD_BYTES,
	                                               MULTI_DSTBLT_ORDER_FIELD_BYTES,
	                                               MULTI_PATBLT_ORDER_FIELD_BYTES,
	                                               MULTI_SCRBLT_ORDER_FIELD_BYTES,
	                                               MULTI_OPAQUE_RECT_ORDER_FIELD_BYTES,
	                                               FAST_INDEX_ORDER_FIELD_BYTES,
	                                               POLYGON_SC_ORDER_FIELD_BYTES,
	                                               POLYGON_CB_ORDER_FIELD_BYTES,
	                                               POLYLINE_ORDER_FIELD_BYTES,
	                                               0,
	                                               FAST_GLYPH_ORDER_FIELD_BYTES,
	                                               ELLIPSE_SC_ORDER_FIELD_BYTES,
	                                               ELLIPSE_CB_ORDER_FIELD_BYTES,
	                                               GLYPH_INDEX_ORDER_FIELD_BYTES };

#define PRIMARY_DRAWING_ORDER_COUNT (ARRAYSIZE(PRIMARY_DRAWING_ORDER_FIELD_BYTES))

static const BYTE CBR2_BPP[] = { 0, 0, 0, 8, 16, 24, 32 };

static const BYTE BPP_CBR2[] = { 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
	                             0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0 };

static const BYTE CBR23_BPP[] = { 0, 0, 0, 8, 16, 24, 32 };

static const BYTE BPP_CBR23[] = { 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
	                              0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0 };
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,36 +43,75 @@
 
 #define TAG FREERDP_TAG("core.orders")
 
-const BYTE PRIMARY_DRAWING_ORDER_FIELD_BYTES[] = { DSTBLT_ORDER_FIELD_BYTES,
-	                                               PATBLT_ORDER_FIELD_BYTES,
-	                                               SCRBLT_ORDER_FIELD_BYTES,
-	                                               0,
-	                                               0,
-	                                               0,
-	                                               0,
-	                                               DRAW_NINE_GRID_ORDER_FIELD_BYTES,
-	                                               MULTI_DRAW_NINE_GRID_ORDER_FIELD_BYTES,
-	                                               LINE_TO_ORDER_FIELD_BYTES,
-	                                               OPAQUE_RECT_ORDER_FIELD_BYTES,
-	                                               SAVE_BITMAP_ORDER_FIELD_BYTES,
-	                                               0,
-	                                               MEMBLT_ORDER_FIELD_BYTES,
-	                                               MEM3BLT_ORDER_FIELD_BYTES,
-	                                               MULTI_DSTBLT_ORDER_FIELD_BYTES,
-	                                               MULTI_PATBLT_ORDER_FIELD_BYTES,
-	                                               MULTI_SCRBLT_ORDER_FIELD_BYTES,
-	                                               MULTI_OPAQUE_RECT_ORDER_FIELD_BYTES,
-	                                               FAST_INDEX_ORDER_FIELD_BYTES,
-	                                               POLYGON_SC_ORDER_FIELD_BYTES,
-	                                               POLYGON_CB_ORDER_FIELD_BYTES,
-	                                               POLYLINE_ORDER_FIELD_BYTES,
-	                                               0,
-	                                               FAST_GLYPH_ORDER_FIELD_BYTES,
-	                                               ELLIPSE_SC_ORDER_FIELD_BYTES,
-	                                               ELLIPSE_CB_ORDER_FIELD_BYTES,
-	                                               GLYPH_INDEX_ORDER_FIELD_BYTES };
-
-#define PRIMARY_DRAWING_ORDER_COUNT (ARRAYSIZE(PRIMARY_DRAWING_ORDER_FIELD_BYTES))
+BYTE get_primary_drawing_order_field_bytes(UINT32 orderType, BOOL* pValid)
+{
+	if (pValid)
+		*pValid = TRUE;
+	switch (orderType)
+	{
+		case 0:
+			return DSTBLT_ORDER_FIELD_BYTES;
+		case 1:
+			return PATBLT_ORDER_FIELD_BYTES;
+		case 2:
+			return SCRBLT_ORDER_FIELD_BYTES;
+		case 3:
+			return 0;
+		case 4:
+			return 0;
+		case 5:
+			return 0;
+		case 6:
+			return 0;
+		case 7:
+			return DRAW_NINE_GRID_ORDER_FIELD_BYTES;
+		case 8:
+			return MULTI_DRAW_NINE_GRID_ORDER_FIELD_BYTES;
+		case 9:
+			return LINE_TO_ORDER_FIELD_BYTES;
+		case 10:
+			return OPAQUE_RECT_ORDER_FIELD_BYTES;
+		case 11:
+			return SAVE_BITMAP_ORDER_FIELD_BYTES;
+		case 12:
+			return 0;
+		case 13:
+			return MEMBLT_ORDER_FIELD_BYTES;
+		case 14:
+			return MEM3BLT_ORDER_FIELD_BYTES;
+		case 15:
+			return MULTI_DSTBLT_ORDER_FIELD_BYTES;
+		case 16:
+			return MULTI_PATBLT_ORDER_FIELD_BYTES;
+		case 17:
+			return MULTI_SCRBLT_ORDER_FIELD_BYTES;
+		case 18:
+			return MULTI_OPAQUE_RECT_ORDER_FIELD_BYTES;
+		case 19:
+			return FAST_INDEX_ORDER_FIELD_BYTES;
+		case 20:
+			return POLYGON_SC_ORDER_FIELD_BYTES;
+		case 21:
+			return POLYGON_CB_ORDER_FIELD_BYTES;
+		case 22:
+			return POLYLINE_ORDER_FIELD_BYTES;
+		case 23:
+			return 0;
+		case 24:
+			return FAST_GLYPH_ORDER_FIELD_BYTES;
+		case 25:
+			return ELLIPSE_SC_ORDER_FIELD_BYTES;
+		case 26:
+			return ELLIPSE_CB_ORDER_FIELD_BYTES;
+		case 27:
+			return GLYPH_INDEX_ORDER_FIELD_BYTES;
+		default:
+			if (pValid)
+				*pValid = FALSE;
+			WLog_WARN(TAG, "Invalid orderType 0x%08X received", orderType);
+			return 0;
+	}
+}
 
 static const BYTE CBR2_BPP[] = { 0, 0, 0, 8, 16, 24, 32 };
 
@@ -3240,6 +3279,7 @@
 
 static BOOL update_recv_primary_order(rdpUpdate* update, wStream* s, BYTE flags)
 {
+	BYTE field;
 	BOOL rc = FALSE;
 	rdpContext* context = update->context;
 	rdpPrimaryUpdate* primary = update->primary;
@@ -3263,8 +3303,11 @@
 	if (!check_primary_order_supported(update->log, settings, orderInfo->orderType, orderName))
 		return FALSE;
 
-	if (!update_read_field_flags(s, &(orderInfo->fieldFlags), flags,
-	                             PRIMARY_DRAWING_ORDER_FIELD_BYTES[orderInfo->orderType]))
+	field = get_primary_drawing_order_field_bytes(orderInfo->orderType, &rc);
+	if (!rc)
+		return FALSE;
+
+	if (!update_read_field_flags(s, &(orderInfo->fieldFlags), flags, field))
 	{
 		WLog_Print(update->log, WLOG_ERROR, "update_read_field_flags() failed");
 		return FALSE;
```
