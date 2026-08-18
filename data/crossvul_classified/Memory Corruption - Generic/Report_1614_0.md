# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1614_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1614_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 309-350 of the vulnerable file.

		body->frame_number = (u8)unit_count;
		oz_usb_submit_elt(eb, ei, usb_ctx, ep_num,
			pd->mode & OZ_F_ISOC_ANYTIME);
	}
	return 0;
}

/*
 * Context: softirq-serialized
 */
static void oz_usb_handle_ep_data(struct oz_usb_ctx *usb_ctx,
	struct oz_usb_hdr *usb_hdr, int len)
{
	struct oz_data *data_hdr = (struct oz_data *)usb_hdr;

	switch (data_hdr->format) {
	case OZ_DATA_F_MULTIPLE_FIXED: {
			struct oz_multiple_fixed *body =
				(struct oz_multiple_fixed *)data_hdr;
			u8 *data = body->data;
			int n;
			if (!body->unit_size)
				break;
			n = (len - sizeof(struct oz_multiple_fixed)+1)
				/ body->unit_size;
			while (n--) {
				oz_hcd_data_ind(usb_ctx->hport, body->endpoint,
					data, body->unit_size);
				data += body->unit_size;
			}
		}
		break;
	case OZ_DATA_F_ISOC_FIXED: {
			struct oz_isoc_fixed *body =
				(struct oz_isoc_fixed *)data_hdr;
			int data_len = len-sizeof(struct oz_isoc_fixed)+1;
			int unit_size = body->unit_size;
			u8 *data = body->data;
			int count;
			int i;

			if (!unit_size)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -326,10 +326,11 @@
 			struct oz_multiple_fixed *body =
 				(struct oz_multiple_fixed *)data_hdr;
 			u8 *data = body->data;
-			int n;
-			if (!body->unit_size)
+			unsigned int n;
+			if (!body->unit_size ||
+				len < sizeof(struct oz_multiple_fixed) - 1)
 				break;
-			n = (len - sizeof(struct oz_multiple_fixed)+1)
+			n = (len - (sizeof(struct oz_multiple_fixed) - 1))
 				/ body->unit_size;
 			while (n--) {
 				oz_hcd_data_ind(usb_ctx->hport, body->endpoint,
```
