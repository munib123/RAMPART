# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5108_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5108_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1666-1706 of the vulnerable file.

    gint command_id = -1;
    gint status = 0;
    guint prefix = 0;
    proto_item *ti = NULL;
    proto_item *item = NULL;
    const char *command_string;
    usb_conv_info_t *usb_conv_info;
    gint stream_detected = FALSE;
    gint control_detected = FALSE;
    u3v_conv_info_t *u3v_conv_info = NULL;
    gencp_transaction_t *gencp_trans = NULL;

    usb_conv_info = (usb_conv_info_t *)data;

    /* decide if this packet belongs to U3V protocol */
    u3v_conv_info = (u3v_conv_info_t *)usb_conv_info->class_data;

    if (!u3v_conv_info) {
        u3v_conv_info = wmem_new0(wmem_file_scope(), u3v_conv_info_t);
        usb_conv_info->class_data = u3v_conv_info;
    }

    prefix = tvb_get_letohl(tvb, 0);
    if ((tvb_reported_length(tvb) >= 4) && ( ( U3V_CONTROL_PREFIX == prefix ) || ( U3V_EVENT_PREFIX == prefix ) ) ) {
        control_detected = TRUE;
    }

    if (((tvb_reported_length(tvb) >= 4) && (( U3V_STREAM_LEADER_PREFIX == prefix ) || ( U3V_STREAM_TRAILER_PREFIX == prefix )))
         || (usb_conv_info->endpoint == u3v_conv_info->ep_stream)) {
        stream_detected = TRUE;
    }

    /* initialize interface class/subclass in case no descriptors have been dissected yet */
    if ( control_detected || stream_detected){
        if ( usb_conv_info->interfaceClass  == IF_CLASS_UNKNOWN &&
             usb_conv_info->interfaceSubclass  == IF_SUBCLASS_UNKNOWN){
            usb_conv_info->interfaceClass = IF_CLASS_MISCELLANEOUS;
            usb_conv_info->interfaceSubclass = IF_SUBCLASS_MISC_U3V;
        }
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1683,6 +1683,10 @@
     if (!u3v_conv_info) {
         u3v_conv_info = wmem_new0(wmem_file_scope(), u3v_conv_info_t);
         usb_conv_info->class_data = u3v_conv_info;
+        usb_conv_info->class_data_type = USB_CONV_U3V;
+    } else if (usb_conv_info->class_data_type != USB_CONV_U3V) {
+        /* Don't dissect if another USB type is in the conversation */
+        return 0;
     }
 
     prefix = tvb_get_letohl(tvb, 0);
```
