# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3415_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3415_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 158-198 of the vulnerable file.

        }

        if (bitbuf & mask) {
            v = bytestream2_get_le16(gb);
            offset = (v & 0x1FFF) << 2;
            count = ((v >> 13) + 2) << 1;
            if (frame - frame_start < offset || frame_end - frame < count*2 + width)
                return AVERROR_INVALIDDATA;
            for (i = 0; i < count; i++) {
                frame[0] = frame[1] =
                frame[width] = frame[width + 1] = frame[-offset];

                frame += 2;
            }
        } else if (bitbuf & (mask << 1)) {
            v = bytestream2_get_le16(gb)*2;
            if (frame - frame_end < v)
                return AVERROR_INVALIDDATA;
            frame += v;
        } else {
            if (frame_end - frame < width + 3)
                return AVERROR_INVALIDDATA;
            frame[0] = frame[1] =
            frame[width] = frame[width + 1] =  bytestream2_get_byte(gb);
            frame += 2;
            frame[0] = frame[1] =
            frame[width] = frame[width + 1] =  bytestream2_get_byte(gb);
            frame += 2;
        }
        mask <<= 2;
    }

    return 0;
}

static int decode_bdlt(GetByteContext *gb, uint8_t *frame, int width, int height)
{
    uint8_t *line_ptr;
    int count, lines, segments;

    count = bytestream2_get_le16(gb);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -175,7 +175,7 @@
                 return AVERROR_INVALIDDATA;
             frame += v;
         } else {
-            if (frame_end - frame < width + 3)
+            if (frame_end - frame < width + 4)
                 return AVERROR_INVALIDDATA;
             frame[0] = frame[1] =
             frame[width] = frame[width + 1] =  bytestream2_get_byte(gb);
```
