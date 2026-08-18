# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3951_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3951_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1070-1110 of the vulnerable file.


		if (update->previousBounds.bottom != update->currentBounds.bottom)
		{
			orderInfo->bounds.bottom = update->currentBounds.bottom;
			orderInfo->boundsFlags |= BOUND_BOTTOM;
			length += 2;
		}
	}

	return length;
}

static int update_prepare_order_info(rdpContext* context, ORDER_INFO* orderInfo, UINT32 orderType)
{
	int length = 1;
	orderInfo->fieldFlags = 0;
	orderInfo->orderType = orderType;
	orderInfo->controlFlags = ORDER_STANDARD;
	orderInfo->controlFlags |= ORDER_TYPE_CHANGE;
	length += 1;
	length += PRIMARY_DRAWING_ORDER_FIELD_BYTES[orderInfo->orderType];
	length += update_prepare_bounds(context, orderInfo);
	return length;
}

static int update_write_order_info(rdpContext* context, wStream* s, ORDER_INFO* orderInfo,
                                   size_t offset)
{
	size_t position;
	WINPR_UNUSED(context);
	position = Stream_GetPosition(s);
	Stream_SetPosition(s, offset);
	Stream_Write_UINT8(s, orderInfo->controlFlags); /* controlFlags (1 byte) */

	if (orderInfo->controlFlags & ORDER_TYPE_CHANGE)
		Stream_Write_UINT8(s, orderInfo->orderType); /* orderType (1 byte) */

	update_write_field_flags(s, orderInfo->fieldFlags, orderInfo->controlFlags,
	                         PRIMARY_DRAWING_ORDER_FIELD_BYTES[orderInfo->orderType]);
	update_write_bounds(s, orderInfo);
	Stream_SetPosition(s, position);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1087,7 +1087,7 @@
 	orderInfo->controlFlags = ORDER_STANDARD;
 	orderInfo->controlFlags |= ORDER_TYPE_CHANGE;
 	length += 1;
-	length += PRIMARY_DRAWING_ORDER_FIELD_BYTES[orderInfo->orderType];
+	length += get_primary_drawing_order_field_bytes(orderInfo->orderType, NULL);
 	length += update_prepare_bounds(context, orderInfo);
 	return length;
 }
@@ -1105,7 +1105,7 @@
 		Stream_Write_UINT8(s, orderInfo->orderType); /* orderType (1 byte) */
 
 	update_write_field_flags(s, orderInfo->fieldFlags, orderInfo->controlFlags,
-	                         PRIMARY_DRAWING_ORDER_FIELD_BYTES[orderInfo->orderType]);
+	                         get_primary_drawing_order_field_bytes(orderInfo->orderType, NULL));
 	update_write_bounds(s, orderInfo);
 	Stream_SetPosition(s, position);
 	return 0;
```
