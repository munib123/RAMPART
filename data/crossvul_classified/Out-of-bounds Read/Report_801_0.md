# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 801_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `801_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1882-1922 of the vulnerable file.

        additional_code_len = ac_state_tab[group][0];
        cur_vlc = &ctx->studio_intra_tab[ac_state_tab[group][1]];

        if (group == 0) {
            /* End of Block */
            break;
        } else if (group >= 1 && group <= 6) {
            /* Zero run length (Table B.47) */
            run = 1 << additional_code_len;
            if (additional_code_len)
                run += get_bits(&s->gb, additional_code_len);
            idx += run;
            continue;
        } else if (group >= 7 && group <= 12) {
            /* Zero run length and +/-1 level (Table B.48) */
            code = get_bits(&s->gb, additional_code_len);
            sign = code & 1;
            code >>= 1;
            run = (1 << (additional_code_len - 1)) + code;
            idx += run;
            j = scantable[idx++];
            block[j] = sign ? 1 : -1;
        } else if (group >= 13 && group <= 20) {
            /* Level value (Table B.49) */
            j = scantable[idx++];
            block[j] = get_xbits(&s->gb, additional_code_len);
        } else if (group == 21) {
            /* Escape */
            j = scantable[idx++];
            additional_code_len = s->avctx->bits_per_raw_sample + s->dct_precision + 4;
            flc = get_bits(&s->gb, additional_code_len);
            if (flc >> (additional_code_len-1))
                block[j] = -1 * (( flc ^ ((1 << additional_code_len) -1)) + 1);
            else
                block[j] = flc;
        }
        block[j] = ((8 * 2 * block[j] * quant_matrix[j] * s->qscale) >> s->dct_precision) / 32;
        block[j] = av_clip(block[j], min, max);
        mismatch ^= block[j];
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1899,14 +1899,20 @@
             code >>= 1;
             run = (1 << (additional_code_len - 1)) + code;
             idx += run;
+            if (idx > 63)
+                return AVERROR_INVALIDDATA;
             j = scantable[idx++];
             block[j] = sign ? 1 : -1;
         } else if (group >= 13 && group <= 20) {
             /* Level value (Table B.49) */
+            if (idx > 63)
+                return AVERROR_INVALIDDATA;
             j = scantable[idx++];
             block[j] = get_xbits(&s->gb, additional_code_len);
         } else if (group == 21) {
             /* Escape */
+            if (idx > 63)
+                return AVERROR_INVALIDDATA;
             j = scantable[idx++];
             additional_code_len = s->avctx->bits_per_raw_sample + s->dct_precision + 4;
             flc = get_bits(&s->gb, additional_code_len);
```
