# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2588_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2588_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 218-258 of the vulnerable file.


        // Start of Midi Data
        chunk_delta[i] = 0;
        var_len_shift = 0;
        if (*hmp_data < 0x80) {
            do {
                chunk_delta[i] = chunk_delta[i] | ((*hmp_data++ & 0x7F) << var_len_shift);
                var_len_shift += 7;
                chunk_ofs[i]++;
            } while (*hmp_data < 0x80);
        }
        chunk_delta[i] = chunk_delta[i] | ((*hmp_data++ & 0x7F) << var_len_shift);
        chunk_ofs[i]++;

        if (chunk_delta[i] < smallest_delta) {
            smallest_delta = chunk_delta[i];
        }

        // goto start of next chunk
        hmp_data = hmp_chunk[i] + chunk_length[i];
        hmp_chunk[i] += chunk_ofs[i]++;
        chunk_end[i] = 0;
    }

    subtract_delta = smallest_delta;
    sample_count_f = (((float) smallest_delta * samples_per_delta_f) + sample_remainder);

    sample_count = (uint32_t) sample_count_f;
    sample_remainder = sample_count_f - (float) sample_count;

    hmp_mdi->events[hmp_mdi->event_count - 1].samples_to_next += sample_count;
    hmp_mdi->extra_info.approx_total_samples += sample_count;

    while (end_of_chunks < hmp_chunks) {
        smallest_delta = 0;

        // DEBUG
        // fprintf(stderr,"DEBUG: Delta Ticks: %u\r\n",subtract_delta);

        for (i = 0; i < hmp_chunks; i++) {
            if (chunk_end[i])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -235,6 +235,7 @@
 
         // goto start of next chunk
         hmp_data = hmp_chunk[i] + chunk_length[i];
+        chunk_length[i] -= chunk_ofs[i];
         hmp_chunk[i] += chunk_ofs[i]++;
         chunk_end[i] = 0;
     }
@@ -273,10 +274,11 @@
                     // Reserved for loop markers
                     // TODO: still deciding what to do about these
                     hmp_chunk[i] += 3;
+                    chunk_length[i] -= 3;
                 } else {
                     uint32_t setup_ret = 0;
 
-                    if ((setup_ret = _WM_SetupMidiEvent(hmp_mdi, hmp_chunk[i], 0)) == 0) {
+                    if ((setup_ret = _WM_SetupMidiEvent(hmp_mdi, hmp_chunk[i], chunk_length[i], 0)) == 0) {
                         goto _hmp_end;
                     }
 
@@ -284,6 +286,7 @@
                         /* End of Chunk */
                         end_of_chunks++;
                         chunk_end[i] = 1;
+                        chunk_length[i] -= 3;
                         hmp_chunk[i] += 3;
                         goto NEXT_CHUNK;
                     } else if ((hmp_chunk[i][0] == 0xff) && (hmp_chunk[i][1] == 0x51) && (hmp_chunk[i][2] == 0x03)) {
@@ -296,18 +299,26 @@
                         fprintf(stderr,"DEBUG: Tempo change %f\r\n", tempo_f);
                     }
                     hmp_chunk[i] += setup_ret;
+                    chunk_length[i] -= setup_ret;
                 }
                 var_len_shift = 0;
                 chunk_delta[i] = 0;
-                if (*hmp_chunk[i] < 0x80) {
+                if (chunk_length[i] && *hmp_chunk[i] < 0x80) {
                     do {
+                        if (! chunk_length[i]) break;
                         chunk_delta[i] = chunk_delta[i] + ((*hmp_chunk[i] & 0x7F) << var_len_shift);
                         var_len_shift += 7;
                         hmp_chunk[i]++;
+                        chunk_length[i]--;
                     } while (*hmp_chunk[i] < 0x80);
+                }
+                if (! chunk_length[i]) {
+                    _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMP, "file too short", 0);
+                    goto _hmp_end;
                 }
                 chunk_delta[i] = chunk_delta[i] + ((*hmp_chunk[i] & 0x7F) << var_len_shift);
                 hmp_chunk[i]++;
+                chunk_length[i]--;
             } while (!chunk_delta[i]);
 
             if ((!smallest_delta) || (smallest_delta > chunk_delta[i])) {
```
