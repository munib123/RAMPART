# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2131_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2131_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 328-368 of the vulnerable file.

0xA1, 0x02,         /*      Collection (Logical),           */
0x09, 0x02,         /*          Usage (02h),                */
0x95, 0x07,         /*          Report Count (7),           */
0x91, 0x02,         /*          Output (Variable),          */
0xC0,               /*      End Collection,                 */
0xC0                /*  End Collection                      */
};

/*
 * Certain Logitech keyboards send in report #3 keys which are far
 * above the logical maximum described in descriptor. This extends
 * the original value of 0x28c of logical maximum to 0x104d
 */
static __u8 *lg_report_fixup(struct hid_device *hdev, __u8 *rdesc,
		unsigned int *rsize)
{
	struct lg_drv_data *drv_data = hid_get_drvdata(hdev);
	struct usb_device_descriptor *udesc;
	__u16 bcdDevice, rev_maj, rev_min;

	if ((drv_data->quirks & LG_RDESC) && *rsize >= 90 && rdesc[83] == 0x26 &&
			rdesc[84] == 0x8c && rdesc[85] == 0x02) {
		hid_info(hdev,
			 "fixing up Logitech keyboard report descriptor\n");
		rdesc[84] = rdesc[89] = 0x4d;
		rdesc[85] = rdesc[90] = 0x10;
	}
	if ((drv_data->quirks & LG_RDESC_REL_ABS) && *rsize >= 50 &&
			rdesc[32] == 0x81 && rdesc[33] == 0x06 &&
			rdesc[49] == 0x81 && rdesc[50] == 0x06) {
		hid_info(hdev,
			 "fixing up rel/abs in Logitech report descriptor\n");
		rdesc[33] = rdesc[50] = 0x02;
	}

	switch (hdev->product) {

	/* Several wheels report as this id when operating in emulation mode. */
	case USB_DEVICE_ID_LOGITECH_WHEEL:
		udesc = &(hid_to_usb_dev(hdev)->descriptor);
		if (!udesc) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -345,14 +345,14 @@
 	struct usb_device_descriptor *udesc;
 	__u16 bcdDevice, rev_maj, rev_min;
 
-	if ((drv_data->quirks & LG_RDESC) && *rsize >= 90 && rdesc[83] == 0x26 &&
+	if ((drv_data->quirks & LG_RDESC) && *rsize >= 91 && rdesc[83] == 0x26 &&
 			rdesc[84] == 0x8c && rdesc[85] == 0x02) {
 		hid_info(hdev,
 			 "fixing up Logitech keyboard report descriptor\n");
 		rdesc[84] = rdesc[89] = 0x4d;
 		rdesc[85] = rdesc[90] = 0x10;
 	}
-	if ((drv_data->quirks & LG_RDESC_REL_ABS) && *rsize >= 50 &&
+	if ((drv_data->quirks & LG_RDESC_REL_ABS) && *rsize >= 51 &&
 			rdesc[32] == 0x81 && rdesc[33] == 0x06 &&
 			rdesc[49] == 0x81 && rdesc[50] == 0x06) {
 		hid_info(hdev,
```
