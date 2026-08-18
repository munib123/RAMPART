# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4485_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4485_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1813-1853 of the vulnerable file.

        bytestream2_init_writer(&offset_table_writer, &avpkt->data[start_offset_table], nb_blocks * 8);

        for (y = 0; y < nb_blocks; y++) {
            /* write offset of prev scanline in offset table */
            bytestream2_put_le64(&offset_table_writer, start_next_scanline);

            /* get len of next scanline */
            bytestream2_seek(&s->gb, start_next_scanline + 4, SEEK_SET);/* skip line number */
            start_next_scanline += (bytestream2_get_le32(&s->gb) + 8);
        }
        bytestream2_seek(&s->gb, start_offset_table, SEEK_SET);
    }

    // save pointer we are going to use in decode_block
    s->buf      = avpkt->data;
    s->buf_size = avpkt->size;

    // Zero out the start if ymin is not 0
    for (i = 0; i < planes; i++) {
        ptr = picture->data[i];
        for (y = 0; y < s->ymin; y++) {
            memset(ptr, 0, out_line_size);
            ptr += picture->linesize[i];
        }
    }

    s->picture = picture;

    avctx->execute2(avctx, decode_block, s->thread_data, NULL, nb_blocks);

    ymax = FFMAX(0, s->ymax + 1);
    // Zero out the end if ymax+1 is not h
    for (i = 0; i < planes; i++) {
        ptr = picture->data[i] + (ymax * picture->linesize[i]);
        for (y = ymax; y < avctx->height; y++) {
            memset(ptr, 0, out_line_size);
            ptr += picture->linesize[i];
        }
    }

    picture->pict_type = AV_PICTURE_TYPE_I;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1830,7 +1830,7 @@
     // Zero out the start if ymin is not 0
     for (i = 0; i < planes; i++) {
         ptr = picture->data[i];
-        for (y = 0; y < s->ymin; y++) {
+        for (y = 0; y < FFMIN(s->ymin, s->h); y++) {
             memset(ptr, 0, out_line_size);
             ptr += picture->linesize[i];
         }
```
