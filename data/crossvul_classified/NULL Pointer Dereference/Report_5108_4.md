# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5108_4
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5108_4`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 73-113 of the vulnerable file.

    union {
        struct {
            guint8 type;
            guint8 usb_index;
        } get_descriptor;
    } u;


    /* used to pass the interface class from the
     * interface descriptor onto the endpoint
     * descriptors so that we can create a
     * conversation with the appropriate class
     * once we know the endpoint.
     * Valid only during GET CONFIGURATION response.
     */
    usb_conv_info_t *interface_info;

    guint64 usb_id;
} usb_trans_info_t;

/* Conversation Structure
 * there is one such structure for each device/endpoint conversation */
struct _usb_conv_info_t {
    guint16  bus_id;
    guint16  device_address;
    guint8   endpoint;
    gint     direction;
    guint8   transfer_type;
    guint32  device_protocol;
    gboolean is_request;
    gboolean is_setup;
    guint8   setup_requesttype;

    guint16 interfaceClass;     /* Interface Descriptor - class          */
    guint16 interfaceSubclass;  /* Interface Descriptor - subclass       */
    guint16 interfaceProtocol;  /* Interface Descriptor - protocol       */
    guint8  interfaceNum;       /* Most recent interface number          */

    guint16 deviceVendor;       /* Device    Descriptor - USB Vendor  ID */
    guint32 deviceProduct;      /* Device    Descriptor - USB Product ID - MSBs only for encoding unknown */
    wmem_tree_t *transactions;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,6 +89,8 @@
 
     guint64 usb_id;
 } usb_trans_info_t;
+
+enum usb_conv_class_data_type {USB_CONV_UNKNOWN = 0, USB_CONV_U3V, USB_CONV_AUDIO, USB_CONV_VIDEO, USB_CONV_MASS_STORAGE};
 
 /* Conversation Structure
  * there is one such structure for each device/endpoint conversation */
@@ -113,7 +115,8 @@
     wmem_tree_t *transactions;
     usb_trans_info_t *usb_trans_info; /* pointer to the current transaction */
 
-    void *class_data;	/* private class/id decode data */
+    void *class_data;           /* private class/id decode data */
+    enum usb_conv_class_data_type class_data_type;
 
     wmem_array_t *alt_settings;
 };
```
