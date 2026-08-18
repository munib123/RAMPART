# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 96_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `96_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 262-302 of the vulnerable file.


                config->bits_per_sample = 8;
                config->bytes_per_sample = 1;
                config->num_channels = numChannels;
                config->sample_rate = sampleRate / 8;
                config->qmode |= QMODE_DSD_MSB_FIRST;
            }
            else if (debug_logging_mode)
                error_line ("got unknown PROP chunk type \"%c%c%c%c\" of %d bytes",
                    prop_chunk [0], prop_chunk [1], prop_chunk [2], prop_chunk [3], dff_chunk_header.ckDataSize);

            free (prop_chunk);
        }
        else if (!strncmp (dff_chunk_header.ckID, "DSD ", 4)) {
            total_samples = dff_chunk_header.ckDataSize / config->num_channels;
            break;
        }
        else {          // just copy unknown chunks to output file

            int bytes_to_copy = (int)(((dff_chunk_header.ckDataSize) + 1) & ~(int64_t)1);
            char *buff = malloc (bytes_to_copy);

            if (debug_logging_mode)
                error_line ("extra unknown chunk \"%c%c%c%c\" of %d bytes",
                    dff_chunk_header.ckID [0], dff_chunk_header.ckID [1], dff_chunk_header.ckID [2],
                    dff_chunk_header.ckID [3], dff_chunk_header.ckDataSize);

            if (!DoReadFile (infile, buff, bytes_to_copy, &bcount) ||
                bcount != bytes_to_copy ||
                (!(config->qmode & QMODE_NO_STORE_WRAPPER) &&
                !WavpackAddWrapper (wpc, buff, bytes_to_copy))) {
                    error_line ("%s", WavpackGetErrorMessage (wpc));
                    free (buff);
                    return WAVPACK_SOFT_ERROR;
            }

            free (buff);
        }
    }

    if (debug_logging_mode)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -279,7 +279,14 @@
         else {          // just copy unknown chunks to output file
 
             int bytes_to_copy = (int)(((dff_chunk_header.ckDataSize) + 1) & ~(int64_t)1);
-            char *buff = malloc (bytes_to_copy);
+            char *buff;
+
+            if (bytes_to_copy < 0 || bytes_to_copy > 4194304) {
+                error_line ("%s is not a valid .DFF file!", infilename);
+                return WAVPACK_SOFT_ERROR;
+            }
+
+            buff = malloc (bytes_to_copy);
 
             if (debug_logging_mode)
                 error_line ("extra unknown chunk \"%c%c%c%c\" of %d bytes",
```
