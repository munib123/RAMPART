# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 485_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `485_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 815-855 of the vulnerable file.

 *
 * Note: Different kinds of host controller have different "scheduling
 * horizons". While one type might support scheduling only 32 frames
 * into the future, others could support scheduling up to 1024 frames
 * into the future.
 *
 */
int usb_get_current_frame_number(struct usb_device *dev)
{
	return usb_hcd_get_frame_number(dev);
}
EXPORT_SYMBOL_GPL(usb_get_current_frame_number);

/*-------------------------------------------------------------------*/
/*
 * __usb_get_extra_descriptor() finds a descriptor of specific type in the
 * extra field of the interface and endpoint descriptor structs.
 */

int __usb_get_extra_descriptor(char *buffer, unsigned size,
			       unsigned char type, void **ptr)
{
	struct usb_descriptor_header *header;

	while (size >= sizeof(struct usb_descriptor_header)) {
		header = (struct usb_descriptor_header *)buffer;

		if (header->bLength < 2) {
			printk(KERN_ERR
				"%s: bogus descriptor, type %d length %d\n",
				usbcore_name,
				header->bDescriptorType,
				header->bLength);
			return -1;
		}

		if (header->bDescriptorType == type) {
			*ptr = header;
			return 0;
		}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -832,14 +832,14 @@
  */
 
 int __usb_get_extra_descriptor(char *buffer, unsigned size,
-			       unsigned char type, void **ptr)
+			       unsigned char type, void **ptr, size_t minsize)
 {
 	struct usb_descriptor_header *header;
 
 	while (size >= sizeof(struct usb_descriptor_header)) {
 		header = (struct usb_descriptor_header *)buffer;
 
-		if (header->bLength < 2) {
+		if (header->bLength < 2 || header->bLength > size) {
 			printk(KERN_ERR
 				"%s: bogus descriptor, type %d length %d\n",
 				usbcore_name,
@@ -848,7 +848,7 @@
 			return -1;
 		}
 
-		if (header->bDescriptorType == type) {
+		if (header->bDescriptorType == type && header->bLength >= minsize) {
 			*ptr = header;
 			return 0;
 		}
```
