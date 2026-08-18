# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 220_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `220_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 190-230 of the vulnerable file.

                    mquant = -v->pq - mqdiff;                  \
                else                                           \
                    mquant = -get_bits(gb, 5);                 \
            }                                                  \
        }                                                      \
        if (v->dqprofile == DQPROFILE_SINGLE_EDGE)             \
            edges = 1 << v->dqsbedge;                          \
        else if (v->dqprofile == DQPROFILE_DOUBLE_EDGES)       \
            edges = (3 << v->dqsbedge) % 15;                   \
        else if (v->dqprofile == DQPROFILE_FOUR_EDGES)         \
            edges = 15;                                        \
        if ((edges&1) && !s->mb_x)                             \
            mquant = -v->altpq;                                \
        if ((edges&2) && !s->mb_y)                             \
            mquant = -v->altpq;                                \
        if ((edges&4) && s->mb_x == (s->mb_width - 1))         \
            mquant = -v->altpq;                                \
        if ((edges&8) &&                                       \
            s->mb_y == ((s->mb_height >> v->field_mode) - 1))  \
            mquant = -v->altpq;                                \
        if (!mquant || mquant > 31) {                          \
            av_log(v->s.avctx, AV_LOG_ERROR,                   \
                   "Overriding invalid mquant %d\n", mquant);  \
            mquant = 1;                                        \
        }                                                      \
    }

/**
 * @def GET_MVDATA(_dmv_x, _dmv_y)
 * @brief Get MV differentials
 * @see MVDATA decoding from 8.3.5.2, p(1)20
 * @param _dmv_x Horizontal differential for decoded MV
 * @param _dmv_y Vertical differential for decoded MV
 */
#define GET_MVDATA(_dmv_x, _dmv_y)                                      \
    index = 1 + get_vlc2(gb, ff_vc1_mv_diff_vlc[s->mv_table_index].table, \
                         VC1_MV_DIFF_VLC_BITS, 2);                      \
    if (index > 36) {                                                   \
        mb_has_coeffs = 1;                                              \
        index -= 37;                                                    \
    } else                                                              \
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -207,7 +207,7 @@
         if ((edges&8) &&                                       \
             s->mb_y == ((s->mb_height >> v->field_mode) - 1))  \
             mquant = -v->altpq;                                \
-        if (!mquant || mquant > 31) {                          \
+        if (!mquant || mquant > 31 || mquant < -31) {                          \
             av_log(v->s.avctx, AV_LOG_ERROR,                   \
                    "Overriding invalid mquant %d\n", mquant);  \
             mquant = 1;                                        \
```
