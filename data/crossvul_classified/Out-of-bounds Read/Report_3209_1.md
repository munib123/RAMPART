# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3209_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3209_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1524-1564 of the vulnerable file.


  // process the data
  if (magic == 0x414c454d) {
    // magic number that identifies the stream as a uncompressed stream
    dst = calloc(uncompressedSize, 1);
    ALLOCCHECK_CHAR(dst);
    memcpy(dst, src + 4, uncompressedSize);
  } else if (magic == 0x75465a4c) {
    // magic number that identifies the stream as a compressed stream
    int flagCount = 0;
    int flags = 0;
    // Prevent overflow on 32 Bit Systems
    if (comp_Prebuf.size >= INT_MAX - uncompressedSize) {
       printf("Corrupted file\n");
       exit(-1);
    }
    dst = calloc(comp_Prebuf.size + uncompressedSize, 1);
    ALLOCCHECK_CHAR(dst);
    memcpy(dst, comp_Prebuf.data, comp_Prebuf.size);
    out = comp_Prebuf.size;
    while (out < (comp_Prebuf.size + uncompressedSize)) {
      // each flag byte flags 8 literals/references, 1 per bit
      flags = (flagCount++ % 8 == 0) ? src[in++] : flags >> 1;
      if ((flags & 1) == 1) { // each flag bit is 1 for reference, 0 for literal
        unsigned int offset = src[in++];
        unsigned int length = src[in++];
        unsigned int end;
        offset = (offset << 4) | (length >> 4); // the offset relative to block start
        length = (length & 0xF) + 2; // the number of bytes to copy
        // the decompression buffer is supposed to wrap around back
        // to the beginning when the end is reached. we save the
        // need for such a buffer by pointing straight into the data
        // buffer, and simulating this behaviour by modifying the
        // pointers appropriately.
        offset = (out / 4096) * 4096 + offset;
        if (offset >= out) // take from previous block
          offset -= 4096;
        // note: can't use System.arraycopy, because the referenced
        // bytes can cross through the current out position.
        end = offset + length;
        while ((offset < end) && (out < (comp_Prebuf.size + uncompressedSize))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1541,7 +1541,7 @@
     ALLOCCHECK_CHAR(dst);
     memcpy(dst, comp_Prebuf.data, comp_Prebuf.size);
     out = comp_Prebuf.size;
-    while (out < (comp_Prebuf.size + uncompressedSize)) {
+    while ((out < (comp_Prebuf.size + uncompressedSize)) && (in < p->size)) {
       // each flag byte flags 8 literals/references, 1 per bit
       flags = (flagCount++ % 8 == 0) ? src[in++] : flags >> 1;
       if ((flags & 1) == 1) { // each flag bit is 1 for reference, 0 for literal
```
