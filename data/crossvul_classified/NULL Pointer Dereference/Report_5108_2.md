# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5108_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5108_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 182-222 of the vulnerable file.

    proto_tree *tree;
    proto_item *ti;
    guint32 signature=0;
    int offset=0;
    gboolean is_request;
    itl_nexus_t *itl;
    itlq_nexus_t *itlq;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    usb_conv_info = (usb_conv_info_t *)data;

    /* verify that we do have a usb_ms_conv_info */
    usb_ms_conv_info=(usb_ms_conv_info_t *)usb_conv_info->class_data;
    if(!usb_ms_conv_info){
        usb_ms_conv_info=wmem_new(wmem_file_scope(), usb_ms_conv_info_t);
        usb_ms_conv_info->itl=wmem_tree_new(wmem_file_scope());
        usb_ms_conv_info->itlq=wmem_tree_new(wmem_file_scope());
        usb_conv_info->class_data=usb_ms_conv_info;
    }


    is_request=(pinfo->srcport==NO_ENDPOINT);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBMS");

    col_clear(pinfo->cinfo, COL_INFO);


    ti = proto_tree_add_protocol_format(parent_tree, proto_usb_ms, tvb, 0, -1, "USB Mass Storage");
    tree = proto_item_add_subtree(ti, ett_usb_ms);

    signature=tvb_get_letohl(tvb, offset);


    /*
     * SCSI CDB inside CBW
     */
    if(is_request&&(signature==0x43425355)&&(tvb_reported_length(tvb)==31)){
        tvbuff_t *cdb_tvb;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -199,8 +199,11 @@
         usb_ms_conv_info->itl=wmem_tree_new(wmem_file_scope());
         usb_ms_conv_info->itlq=wmem_tree_new(wmem_file_scope());
         usb_conv_info->class_data=usb_ms_conv_info;
-    }
-
+        usb_conv_info->class_data_type = USB_CONV_MASS_STORAGE;
+    } else if (usb_conv_info->class_data_type != USB_CONV_MASS_STORAGE) {
+        /* Don't dissect if another USB type is in the conversation */
+        return 0;
+    }
 
     is_request=(pinfo->srcport==NO_ENDPOINT);
 
```
