# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3142_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3142_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 3422-3462 of the vulnerable file.

            GST_DEBUG ("Skipping empty string value for %s",
                GST_STR_NULL (gst_tag_name));
          }
          g_free (value_utf8);
          break;
        }
        case ASF_DEMUX_DATA_TYPE_BYTE_ARRAY:{
          if (gst_tag_name) {
            if (!g_str_equal (gst_tag_name, GST_TAG_IMAGE)) {
              GST_FIXME ("Unhandled byte array tag %s",
                  GST_STR_NULL (gst_tag_name));
              break;
            } else {
              asf_demux_parse_picture_tag (taglist, (guint8 *) value,
                  value_len);
            }
          }
          break;
        }
        case ASF_DEMUX_DATA_TYPE_DWORD:{
          guint uint_val = GST_READ_UINT32_LE (value);

          /* this is the track number */
          g_value_init (&tag_value, G_TYPE_UINT);

          /* WM/Track counts from 0 */
          if (!strcmp (name_utf8, "WM/Track"))
            ++uint_val;

          g_value_set_uint (&tag_value, uint_val);
          break;
        }
          /* Detect 3D */
        case ASF_DEMUX_DATA_TYPE_BOOL:{
          gboolean bool_val = GST_READ_UINT32_LE (value);

          if (strncmp ("Stereoscopic", name_utf8, strlen (name_utf8)) == 0) {
            if (bool_val) {
              GST_INFO_OBJECT (demux, "This is 3D contents");
              content3D = TRUE;
            } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3439,7 +3439,12 @@
           break;
         }
         case ASF_DEMUX_DATA_TYPE_DWORD:{
-          guint uint_val = GST_READ_UINT32_LE (value);
+          guint uint_val;
+
+          if (value_len < 4)
+            break;
+
+          uint_val = GST_READ_UINT32_LE (value);
 
           /* this is the track number */
           g_value_init (&tag_value, G_TYPE_UINT);
@@ -3453,7 +3458,12 @@
         }
           /* Detect 3D */
         case ASF_DEMUX_DATA_TYPE_BOOL:{
-          gboolean bool_val = GST_READ_UINT32_LE (value);
+          gboolean bool_val;
+
+          if (value_len < 4)
+            break;
+
+          bool_val = GST_READ_UINT32_LE (value);
 
           if (strncmp ("Stereoscopic", name_utf8, strlen (name_utf8)) == 0) {
             if (bool_val) {
```
