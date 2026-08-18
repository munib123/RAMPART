# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1030_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1030_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2287-2327 of the vulnerable file.


    return n;
}

/* Table 4.4.32 */
static uint8_t excluded_channels(bitfile *ld, drc_info *drc)
{
    uint8_t i, n = 0;
    uint8_t num_excl_chan = 7;

    for (i = 0; i < 7; i++)
    {
        drc->exclude_mask[i] = faad_get1bit(ld
            DEBUGVAR(1,103,"excluded_channels(): exclude_mask"));
    }
    n++;

    while ((drc->additional_excluded_chns[n-1] = faad_get1bit(ld
        DEBUGVAR(1,104,"excluded_channels(): additional_excluded_chns"))) == 1)
    {
        for (i = num_excl_chan; i < num_excl_chan+7; i++)
        {
            drc->exclude_mask[i] = faad_get1bit(ld
                DEBUGVAR(1,105,"excluded_channels(): exclude_mask"));
        }
        n++;
        num_excl_chan += 7;
    }

    return n;
}

/* Annex A: Audio Interchange Formats */

/* Table 1.A.2 */
void get_adif_header(adif_header *adif, bitfile *ld)
{
    uint8_t i;

    /* adif_id[0] = */ faad_getbits(ld, 8
        DEBUGVAR(1,106,"get_adif_header(): adif_id[0]"));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2304,6 +2304,8 @@
     while ((drc->additional_excluded_chns[n-1] = faad_get1bit(ld
         DEBUGVAR(1,104,"excluded_channels(): additional_excluded_chns"))) == 1)
     {
+        if (i >= MAX_CHANNELS - num_excl_chan - 7)
+            return n;
         for (i = num_excl_chan; i < num_excl_chan+7; i++)
         {
             drc->exclude_mask[i] = faad_get1bit(ld
```
