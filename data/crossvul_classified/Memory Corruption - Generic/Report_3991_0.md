# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3991_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3991_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 179-219 of the vulnerable file.

            }
            end = start + length;

            i = end;
            if (frag->data[i] != 0xff) {
                next_marker = -1;
            } else {
                for (++i; i + 1 < frag->data_size &&
                          frag->data[i] == 0xff; i++);
                if (i + 1 >= frag->data_size) {
                    next_marker = -1;
                } else {
                    next_marker = frag->data[i];
                    next_start  = i + 1;
                }
            }
        }

        if (marker == JPEG_MARKER_SOS) {
            length = AV_RB16(frag->data + start);

            data_ref = NULL;
            data     = av_malloc(end - start +
                                 AV_INPUT_BUFFER_PADDING_SIZE);
            if (!data)
                return AVERROR(ENOMEM);

            memcpy(data, frag->data + start, length);
            for (i = start + length, j = length; i < end; i++, j++) {
                if (frag->data[i] == 0xff) {
                    while (frag->data[i] == 0xff)
                        ++i;
                    data[j] = 0xff;
                } else {
                    data[j] = frag->data[i];
                }
            }
            data_size = j;

            memset(data + data_size, 0, AV_INPUT_BUFFER_PADDING_SIZE);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -196,6 +196,9 @@
 
         if (marker == JPEG_MARKER_SOS) {
             length = AV_RB16(frag->data + start);
+
+            if (length > end - start)
+                return AVERROR_INVALIDDATA;
 
             data_ref = NULL;
             data     = av_malloc(end - start +
```
