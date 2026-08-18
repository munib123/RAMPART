# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 737_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `737_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 163-203 of the vulnerable file.

            if (debug_logging_mode)
                error_line ("got PROP chunk of %d bytes total", (int) dff_chunk_header.ckDataSize);

            prop_chunk = malloc ((size_t) dff_chunk_header.ckDataSize);

            if (!DoReadFile (infile, prop_chunk, (uint32_t) dff_chunk_header.ckDataSize, &bcount) ||
                bcount != dff_chunk_header.ckDataSize) {
                    error_line ("%s is not a valid .DFF file!", infilename);
                    free (prop_chunk);
                    return WAVPACK_SOFT_ERROR;
            }
            else if (!(config->qmode & QMODE_NO_STORE_WRAPPER) &&
                !WavpackAddWrapper (wpc, prop_chunk, (uint32_t) dff_chunk_header.ckDataSize)) {
                    error_line ("%s", WavpackGetErrorMessage (wpc));
                    free (prop_chunk);
                    return WAVPACK_SOFT_ERROR;
            }

            if (!strncmp (prop_chunk, "SND ", 4)) {
                char *cptr = prop_chunk + 4, *eptr = prop_chunk + dff_chunk_header.ckDataSize;
                uint16_t numChannels, chansSpecified, chanMask = 0;
                uint32_t sampleRate;

                while (eptr - cptr >= sizeof (dff_chunk_header)) {
                    memcpy (&dff_chunk_header, cptr, sizeof (dff_chunk_header));
                    cptr += sizeof (dff_chunk_header);
                    WavpackBigEndianToNative (&dff_chunk_header, DFFChunkHeaderFormat);

                    if (dff_chunk_header.ckDataSize > 0 && dff_chunk_header.ckDataSize <= eptr - cptr) {
                        if (!strncmp (dff_chunk_header.ckID, "FS  ", 4) && dff_chunk_header.ckDataSize == 4) {
                            memcpy (&sampleRate, cptr, sizeof (sampleRate));
                            WavpackBigEndianToNative (&sampleRate, "L");
                            cptr += dff_chunk_header.ckDataSize;

                            if (debug_logging_mode)
                                error_line ("got sample rate of %u Hz", sampleRate);
                        }
                        else if (!strncmp (dff_chunk_header.ckID, "CHNL", 4) && dff_chunk_header.ckDataSize >= 2) {
                            memcpy (&numChannels, cptr, sizeof (numChannels));
                            WavpackBigEndianToNative (&numChannels, "S");
                            cptr += sizeof (numChannels);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -180,7 +180,7 @@
 
             if (!strncmp (prop_chunk, "SND ", 4)) {
                 char *cptr = prop_chunk + 4, *eptr = prop_chunk + dff_chunk_header.ckDataSize;
-                uint16_t numChannels, chansSpecified, chanMask = 0;
+                uint16_t numChannels = 0, chansSpecified, chanMask = 0;
                 uint32_t sampleRate;
 
                 while (eptr - cptr >= sizeof (dff_chunk_header)) {
@@ -204,7 +204,7 @@
 
                             chansSpecified = (int)(dff_chunk_header.ckDataSize - sizeof (numChannels)) / 4;
 
-                            if (numChannels < chansSpecified || numChannels < 1) {
+                            if (numChannels < chansSpecified || numChannels < 1 || numChannels > 256) {
                                 error_line ("%s is not a valid .DFF file!", infilename);
                                 free (prop_chunk);
                                 return WAVPACK_SOFT_ERROR;
@@ -279,6 +279,12 @@
             free (prop_chunk);
         }
         else if (!strncmp (dff_chunk_header.ckID, "DSD ", 4)) {
+
+            if (!config->num_channels) {
+                error_line ("%s is not a valid .DFF file!", infilename);
+                return WAVPACK_SOFT_ERROR;
+            }
+
             total_samples = dff_chunk_header.ckDataSize / config->num_channels;
             break;
         }
```
