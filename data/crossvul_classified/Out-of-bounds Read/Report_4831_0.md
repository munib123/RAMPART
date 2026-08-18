# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4831_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4831_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 543-583 of the vulnerable file.

}

// Read "new" configuration information from metadata.

static int read_new_config_info (WavpackContext *wpc, WavpackMetadata *wpmd)
{
    int bytecnt = wpmd->byte_length;
    unsigned char *byteptr = wpmd->data;

    wpc->version_five = 1;      // just having this block signals version 5.0

    wpc->file_format = wpc->config.qmode = wpc->channel_layout = 0;

    if (wpc->channel_reordering) {
        free (wpc->channel_reordering);
        wpc->channel_reordering = NULL;
    }

    // if there's any data, the first two bytes are file_format and qmode flags

    if (bytecnt) {
        wpc->file_format = *byteptr++;
        wpc->config.qmode = (wpc->config.qmode & ~0xff) | *byteptr++;
        bytecnt -= 2;

        // another byte indicates a channel layout

        if (bytecnt) {
            int nchans, i;

            wpc->channel_layout = (int32_t) *byteptr++ << 16;
            bytecnt--;

            // another byte means we have a channel count for the layout and maybe a reordering

            if (bytecnt) {
                wpc->channel_layout += nchans = *byteptr++;
                bytecnt--;

                // any more means there's a reordering string

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -560,7 +560,7 @@
 
     // if there's any data, the first two bytes are file_format and qmode flags
 
-    if (bytecnt) {
+    if (bytecnt >= 2) {
         wpc->file_format = *byteptr++;
         wpc->config.qmode = (wpc->config.qmode & ~0xff) | *byteptr++;
         bytecnt -= 2;
@@ -593,6 +593,10 @@
                         for (i = 0; i < nchans; ++i)
                             if (bytecnt) {
                                 wpc->channel_reordering [i] = *byteptr++;
+
+                                if (wpc->channel_reordering [i] >= nchans)  // make sure index is in range
+                                    wpc->channel_reordering [i] = 0;
+
                                 bytecnt--;
                             }
                             else
```
