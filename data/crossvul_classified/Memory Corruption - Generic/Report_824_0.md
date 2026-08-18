# CrossVul Fix Pair: Access of Uninitialized Pointer in c
**Pair ID:** 824_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-824
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `824_0`)

## Vulnerability Information & PoC

## Description
Access of Uninitialized Pointer - If the pointer contains an uninitialized value, then the value might not point to a valid memory location.

## Vulnerable Code
```c
Lines 164-204 of the vulnerable file.

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
                uint16_t numChannels = 0, chansSpecified, chanMask = 0;
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
@@ -181,7 +181,7 @@
             if (!strncmp (prop_chunk, "SND ", 4)) {
                 char *cptr = prop_chunk + 4, *eptr = prop_chunk + dff_chunk_header.ckDataSize;
                 uint16_t numChannels = 0, chansSpecified, chanMask = 0;
-                uint32_t sampleRate;
+                uint32_t sampleRate = 0;
 
                 while (eptr - cptr >= sizeof (dff_chunk_header)) {
                     memcpy (&dff_chunk_header, cptr, sizeof (dff_chunk_header));
@@ -280,7 +280,7 @@
         }
         else if (!strncmp (dff_chunk_header.ckID, "DSD ", 4)) {
 
-            if (!config->num_channels) {
+            if (!config->num_channels || !config->sample_rate) {
                 error_line ("%s is not a valid .DFF file!", infilename);
                 return WAVPACK_SOFT_ERROR;
             }
```
