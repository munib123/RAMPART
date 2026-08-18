# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2589_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2589_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 488-528 of the vulnerable file.

    }
}

int ff_amf_tag_size(const uint8_t *data, const uint8_t *data_end)
{
    GetByteContext gb;
    int ret;

    if (data >= data_end)
        return -1;

    bytestream2_init(&gb, data, data_end - data);

    ret = amf_tag_skip(&gb);
    if (ret < 0 || bytestream2_get_bytes_left(&gb) <= 0)
        return -1;
    av_assert0(bytestream2_tell(&gb) >= 0 && bytestream2_tell(&gb) <= data_end - data);
    return bytestream2_tell(&gb);
}

int ff_amf_get_field_value(const uint8_t *data, const uint8_t *data_end,
                           const uint8_t *name, uint8_t *dst, int dst_size)
{
    int namelen = strlen(name);
    int len;

    while (*data != AMF_DATA_TYPE_OBJECT && data < data_end) {
        len = ff_amf_tag_size(data, data_end);
        if (len < 0)
            len = data_end - data;
        data += len;
    }
    if (data_end - data < 3)
        return -1;
    data++;
    for (;;) {
        int size = bytestream_get_be16(&data);
        if (!size)
            break;
        if (size < 0 || size >= data_end - data)
            return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -505,51 +505,68 @@
     return bytestream2_tell(&gb);
 }
 
-int ff_amf_get_field_value(const uint8_t *data, const uint8_t *data_end,
+static int amf_get_field_value2(GetByteContext *gb,
                            const uint8_t *name, uint8_t *dst, int dst_size)
 {
     int namelen = strlen(name);
     int len;
 
-    while (*data != AMF_DATA_TYPE_OBJECT && data < data_end) {
-        len = ff_amf_tag_size(data, data_end);
-        if (len < 0)
-            len = data_end - data;
-        data += len;
-    }
-    if (data_end - data < 3)
+    while (bytestream2_peek_byte(gb) != AMF_DATA_TYPE_OBJECT && bytestream2_get_bytes_left(gb) > 0) {
+        int ret = amf_tag_skip(gb);
+        if (ret < 0)
+            return -1;
+    }
+    if (bytestream2_get_bytes_left(gb) < 3)
         return -1;
-    data++;
+    bytestream2_get_byte(gb);
+
     for (;;) {
-        int size = bytestream_get_be16(&data);
+        int size = bytestream2_get_be16(gb);
         if (!size)
             break;
-        if (size < 0 || size >= data_end - data)
+        if (size < 0 || size >= bytestream2_get_bytes_left(gb))
             return -1;
-        data += size;
-        if (size == namelen && !memcmp(data-size, name, namelen)) {
-            switch (*data++) {
+        bytestream2_skip(gb, size);
+        if (size == namelen && !memcmp(gb->buffer-size, name, namelen)) {
+            switch (bytestream2_get_byte(gb)) {
             case AMF_DATA_TYPE_NUMBER:
-                snprintf(dst, dst_size, "%g", av_int2double(AV_RB64(data)));
+                snprintf(dst, dst_size, "%g", av_int2double(bytestream2_get_be64(gb)));
                 break;
             case AMF_DATA_TYPE_BOOL:
-                snprintf(dst, dst_size, "%s", *data ? "true" : "false");
+                snprintf(dst, dst_size, "%s", bytestream2_get_byte(gb) ? "true" : "false");
                 break;
             case AMF_DATA_TYPE_STRING:
-                len = bytestream_get_be16(&data);
-                av_strlcpy(dst, data, FFMIN(len+1, dst_size));
+                len = bytestream2_get_be16(gb);
+                if (dst_size < 1)
+                    return -1;
+                if (dst_size < len + 1)
+                    len = dst_size - 1;
+                bytestream2_get_buffer(gb, dst, len);
+                dst[len] = 0;
                 break;
             default:
                 return -1;
             }
             return 0;
         }
-        len = ff_amf_tag_size(data, data_end);
-        if (len < 0 || len >= data_end - data)
+        len = amf_tag_skip(gb);
+        if (len < 0 || bytestream2_get_bytes_left(gb) <= 0)
             return -1;
-        data += len;
     }
     return -1;
+}
+
+int ff_amf_get_field_value(const uint8_t *data, const uint8_t *data_end,
+                           const uint8_t *name, uint8_t *dst, int dst_size)
+{
+    GetByteContext gb;
+
+    if (data >= data_end)
+        return -1;
+
+    bytestream2_init(&gb, data, data_end - data);
+
+    return amf_get_field_value2(&gb, name, dst, dst_size);
 }
 
 static const char* rtmp_packet_type(int type)
```
