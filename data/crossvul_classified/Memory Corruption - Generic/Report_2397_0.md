# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2397_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2397_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 542-582 of the vulnerable file.



static int
rtp_packetize_h264_nal( sout_stream_id_sys_t *id,
                        const uint8_t *p_data, int i_data, int64_t i_pts,
                        int64_t i_dts, bool b_last, int64_t i_length );

int rtp_packetize_xiph_config( sout_stream_id_sys_t *id, const char *fmtp,
                               int64_t i_pts )
{
    if (fmtp == NULL)
        return VLC_EGENERIC;

    /* extract base64 configuration from fmtp */
    char *start = strstr(fmtp, "configuration=");
    assert(start != NULL);
    start += sizeof("configuration=") - 1;
    char *end = strchr(start, ';');
    assert(end != NULL);
    size_t len = end - start;
    char b64[len + 1];
    memcpy(b64, start, len);
    b64[len] = '\0';

    int     i_max   = rtp_mtu (id) - 6; /* payload max in one packet */

    uint8_t *p_orig, *p_data;
    int i_data;

    i_data = vlc_b64_decode_binary(&p_orig, b64);
    if (i_data <= 9)
    {
        free(p_orig);
        return VLC_EGENERIC;
    }
    p_data = p_orig + 9;
    i_data -= 9;

    int i_count = ( i_data + i_max - 1 ) / i_max;

    for( int i = 0; i < i_count; i++ )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -559,7 +559,11 @@
     char *end = strchr(start, ';');
     assert(end != NULL);
     size_t len = end - start;
-    char b64[len + 1];
+
+    char *b64 = malloc(len + 1);
+    if(!b64)
+        return VLC_EGENERIC;
+
     memcpy(b64, start, len);
     b64[len] = '\0';
 
@@ -569,6 +573,7 @@
     int i_data;
 
     i_data = vlc_b64_decode_binary(&p_orig, b64);
+    free(b64);
     if (i_data <= 9)
     {
         free(p_orig);
```
