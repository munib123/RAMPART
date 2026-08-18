# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5108_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5108_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1018-1058 of the vulnerable file.

    if (offset < descriptor_len)
    {
        proto_tree_add_item(tree, hf_usb_vid_descriptor_data, tvb, offset, descriptor_len-offset, ENC_NA);
        /* offset = descriptor_len; */
    }

    if (entity_id != 0)
        proto_item_append_text(item, " (Entity %d)", entity_id);

    if (subtype != VC_HEADER && usb_conv_info)
    {
        /* Switch to the usb_conv_info of the Video Control interface */
        usb_conv_info = get_usb_iface_conv_info(pinfo, usb_conv_info->interfaceNum);
        video_conv_info = (video_conv_info_t *)usb_conv_info->class_data;

        if (!video_conv_info)
        {
            video_conv_info = wmem_new(wmem_file_scope(), video_conv_info_t);
            video_conv_info->entities = wmem_tree_new(wmem_file_scope());
            usb_conv_info->class_data = video_conv_info;
        }

        entity = (video_entity_t*) wmem_tree_lookup32(video_conv_info->entities, entity_id);
        if (!entity)
        {
            entity = wmem_new(wmem_file_scope(), video_entity_t);
            entity->entityID     = entity_id;
            entity->subtype      = subtype;
            entity->terminalType = terminal_type;

            wmem_tree_insert32(video_conv_info->entities, entity_id, entity);
        }
    }

    return descriptor_len;
}

/*****************************************************************************/
/*                        VIDEO STREAMING DESCRIPTORS                        */
/*****************************************************************************/

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1035,6 +1035,10 @@
             video_conv_info = wmem_new(wmem_file_scope(), video_conv_info_t);
             video_conv_info->entities = wmem_tree_new(wmem_file_scope());
             usb_conv_info->class_data = video_conv_info;
+            usb_conv_info->class_data_type = USB_CONV_VIDEO;
+        } else if (usb_conv_info->class_data_type != USB_CONV_VIDEO) {
+            /* Stop dissection if another USB type is in the conversation */
+            return descriptor_len;
         }
 
         entity = (video_entity_t*) wmem_tree_lookup32(video_conv_info->entities, entity_id);
```
