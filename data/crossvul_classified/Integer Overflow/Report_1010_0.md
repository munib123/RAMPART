# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 1010_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1010_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 810-842 of the vulnerable file.

        iIo.write(data, 10);

        /* Handle inject an icc profile right after VP8X chunk */
        if (has_icc) {
            byte size_buff[WEBP_TAG_SIZE];
            ul2Data(size_buff, iccProfile_.size_, littleEndian);
            if (iIo.write((const byte*)WEBP_CHUNK_HEADER_VP8X, WEBP_TAG_SIZE) != WEBP_TAG_SIZE)
                throw Error(kerImageWriteFailed);
            if (iIo.write(size_buff, WEBP_TAG_SIZE) != WEBP_TAG_SIZE)
                throw Error(kerImageWriteFailed);
            if (iIo.write(iccProfile_.pData_, iccProfile_.size_) != iccProfile_.size_)
                throw Error(kerImageWriteFailed);
            if (iIo.tell() % 2) {
                if (iIo.write(&WEBP_PAD_ODD, 1) != 1) throw Error(kerImageWriteFailed);
            }

            has_icc = false;
        }
    }

    long WebPImage::getHeaderOffset(byte *data, long data_size,
                                    byte *header, long header_size) {
        long pos = -1;
        for (long i=0; i < data_size - header_size; i++) {
            if (memcmp(header, &data[i], header_size) == 0) {
                pos = i;
                break;
            }
        }
        return pos;
    }

} // namespace Exiv2
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -827,8 +827,9 @@
         }
     }
 
-    long WebPImage::getHeaderOffset(byte *data, long data_size,
-                                    byte *header, long header_size) {
+    long WebPImage::getHeaderOffset(byte* data, long data_size, byte* header, long header_size)
+    {
+        if (data_size < header_size) { return -1; }
         long pos = -1;
         for (long i=0; i < data_size - header_size; i++) {
             if (memcmp(header, &data[i], header_size) == 0) {
```
