# CrossVul Fix Pair: Improper Validation of Array Index in c
**Pair ID:** 217_0
**Vulnerability Class:** Improper Validation of Array Index
**CWE:** CWE-129
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `217_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Array Index - The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position withi...

## Vulnerable Code
```c
Lines 419-459 of the vulnerable file.

        }

        /* this should always be the case, given that our AC-3 parser
         * concatenates dependent frames to their independent parent */
        if (hdr->frame_type == EAC3_FRAME_TYPE_INDEPENDENT) {
            /* substream ids must be incremental */
            if (hdr->substreamid > info->num_ind_sub + 1) {
                ret = AVERROR(EINVAL);
                goto end;
            }

            if (hdr->substreamid == info->num_ind_sub + 1) {
                //info->num_ind_sub++;
                avpriv_request_sample(track->par, "Multiple independent substreams");
                ret = AVERROR_PATCHWELCOME;
                goto end;
            } else if (hdr->substreamid < info->num_ind_sub ||
                       hdr->substreamid == 0 && info->substream[0].bsid) {
                info->ec3_done = 1;
                goto concatenate;
            }
        }

        /* fill the info needed for the "dec3" atom */
        info->substream[hdr->substreamid].fscod = hdr->sr_code;
        info->substream[hdr->substreamid].bsid  = hdr->bitstream_id;
        info->substream[hdr->substreamid].bsmod = hdr->bitstream_mode;
        info->substream[hdr->substreamid].acmod = hdr->channel_mode;
        info->substream[hdr->substreamid].lfeon = hdr->lfe_on;

        /* Parse dependent substream(s), if any */
        if (pkt->size != hdr->frame_size) {
            int cumul_size = hdr->frame_size;
            int parent = hdr->substreamid;

            while (cumul_size != pkt->size) {
                GetBitContext gbc;
                int i;
                ret = avpriv_ac3_parse_header(&hdr, pkt->data + cumul_size, pkt->size - cumul_size);
                if (ret < 0)
                    goto end;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -436,6 +436,12 @@
                        hdr->substreamid == 0 && info->substream[0].bsid) {
                 info->ec3_done = 1;
                 goto concatenate;
+            }
+        } else {
+            if (hdr->substreamid != 0) {
+                avpriv_request_sample(mov->fc, "Multiple non EAC3 independent substreams");
+                ret = AVERROR_PATCHWELCOME;
+                goto end;
             }
         }
 
```
