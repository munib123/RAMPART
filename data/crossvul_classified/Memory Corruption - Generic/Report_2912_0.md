# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2912_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2912_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 626-666 of the vulnerable file.

				    "interface number: %d but max is %d\n",
				    cfgno, inum, nintf_orig - 1);

			/* Have we already encountered this interface?
			 * Count its altsettings */
			for (i = 0; i < n; ++i) {
				if (inums[i] == inum)
					break;
			}
			if (i < n) {
				if (nalts[i] < 255)
					++nalts[i];
			} else if (n < USB_MAXINTERFACES) {
				inums[n] = inum;
				nalts[n] = 1;
				++n;
			}

		} else if (header->bDescriptorType ==
				USB_DT_INTERFACE_ASSOCIATION) {
			if (iad_num == USB_MAXIADS) {
				dev_warn(ddev, "found more Interface "
					       "Association Descriptors "
					       "than allocated for in "
					       "configuration %d\n", cfgno);
			} else {
				config->intf_assoc[iad_num] =
					(struct usb_interface_assoc_descriptor
					*)header;
				iad_num++;
			}

		} else if (header->bDescriptorType == USB_DT_DEVICE ||
			    header->bDescriptorType == USB_DT_CONFIG)
			dev_warn(ddev, "config %d contains an unexpected "
			    "descriptor of type 0x%X, skipping\n",
			    cfgno, header->bDescriptorType);

	}	/* for ((buffer2 = buffer, size2 = size); ...) */
	size = buffer2 - buffer;
	config->desc.wTotalLength = cpu_to_le16(buffer2 - buffer0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -643,15 +643,23 @@
 
 		} else if (header->bDescriptorType ==
 				USB_DT_INTERFACE_ASSOCIATION) {
+			struct usb_interface_assoc_descriptor *d;
+
+			d = (struct usb_interface_assoc_descriptor *)header;
+			if (d->bLength < USB_DT_INTERFACE_ASSOCIATION_SIZE) {
+				dev_warn(ddev,
+					 "config %d has an invalid interface association descriptor of length %d, skipping\n",
+					 cfgno, d->bLength);
+				continue;
+			}
+
 			if (iad_num == USB_MAXIADS) {
 				dev_warn(ddev, "found more Interface "
 					       "Association Descriptors "
 					       "than allocated for in "
 					       "configuration %d\n", cfgno);
 			} else {
-				config->intf_assoc[iad_num] =
-					(struct usb_interface_assoc_descriptor
-					*)header;
+				config->intf_assoc[iad_num] = d;
 				iad_num++;
 			}
 
```
