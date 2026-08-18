# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2758_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2758_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 612-652 of the vulnerable file.

    OPJ_UINT32 bandno, cblkno;
    OPJ_BYTE* c = dest;
    OPJ_UINT32 l_nb_bytes;
    OPJ_UINT32 compno = pi->compno;     /* component value */
    OPJ_UINT32 resno  = pi->resno;      /* resolution level value */
    OPJ_UINT32 precno = pi->precno;     /* precinct value */
    OPJ_UINT32 layno  = pi->layno;      /* quality layer value */
    OPJ_UINT32 l_nb_blocks;
    opj_tcd_band_t *band = 00;
    opj_tcd_cblk_enc_t* cblk = 00;
    opj_tcd_pass_t *pass = 00;

    opj_tcd_tilecomp_t *tilec = &tile->comps[compno];
    opj_tcd_resolution_t *res = &tilec->resolutions[resno];

    opj_bio_t *bio = 00;    /* BIO component */
    OPJ_BOOL packet_empty = OPJ_TRUE;

    /* <SOP 0xff91> */
    if (tcp->csty & J2K_CP_CSTY_SOP) {
        c[0] = 255;
        c[1] = 145;
        c[2] = 0;
        c[3] = 4;
#if 0
        c[4] = (tile->packno % 65536) / 256;
        c[5] = (tile->packno % 65536) % 256;
#else
        c[4] = (tile->packno >> 8) & 0xff; /* packno is uint32_t */
        c[5] = tile->packno & 0xff;
#endif
        c += 6;
        length -= 6;
    }
    /* </SOP> */

    if (!layno) {
        band = res->bands;

        for (bandno = 0; bandno < res->numbands; ++bandno, ++band) {
            opj_tcd_precinct_t *prc;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -629,6 +629,15 @@
 
     /* <SOP 0xff91> */
     if (tcp->csty & J2K_CP_CSTY_SOP) {
+        if (length < 6) {
+            if (p_t2_mode == FINAL_PASS) {
+                opj_event_msg(p_manager, EVT_ERROR,
+                              "opj_t2_encode_packet(): only %u bytes remaining in "
+                              "output buffer. %u needed.\n",
+                              length, 6);
+            }
+            return OPJ_FALSE;
+        }
         c[0] = 255;
         c[1] = 145;
         c[2] = 0;
@@ -817,6 +826,15 @@
 
     /* <EPH 0xff92> */
     if (tcp->csty & J2K_CP_CSTY_EPH) {
+        if (length < 2) {
+            if (p_t2_mode == FINAL_PASS) {
+                opj_event_msg(p_manager, EVT_ERROR,
+                              "opj_t2_encode_packet(): only %u bytes remaining in "
+                              "output buffer. %u needed.\n",
+                              length, 2);
+            }
+            return OPJ_FALSE;
+        }
         c[0] = 255;
         c[1] = 146;
         c += 2;
```
