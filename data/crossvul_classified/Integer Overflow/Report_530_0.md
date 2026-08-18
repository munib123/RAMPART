# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 530_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `530_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 4146-4186 of the vulnerable file.

                std::pair<std::vector<uint8_t,
                                      Sirikata::JpegAllocator<uint8_t> >,
                          JpegError> uncompressed_header_buffer(
                              ZlibDecoderDecompressionReader::Decompress(compressed_header_buffer.data(),
                                                                         compressed_header_buffer.size(),
                                                                         no_free_allocator,
                                                                         max_file_size + 2048));
                if (uncompressed_header_buffer.second) {
                    always_assert(false && "Data not properly zlib coded");
                    return false;
                }
                zlib_hdrs = compressed_header_buffer.size();
                header_reader->SwapIn(uncompressed_header_buffer.first, 0);
            } else {
                std::pair<std::vector<uint8_t,
                                      Sirikata::JpegAllocator<uint8_t> >,
                          JpegError> uncompressed_header_buffer(
                              Sirikata::BrotliCodec::Decompress(compressed_header_buffer.data(),
                                                                compressed_header_buffer.size(),
                                                                JpegAllocator<uint8_t>(),
                                                                max_file_size * 2 + 128 * 1024 * 1024));
                if (uncompressed_header_buffer.second) {
                    always_assert(false && "Data not properly zlib coded");
                    return false;
                }
                zlib_hdrs = compressed_header_buffer.size();
                header_reader->SwapIn(uncompressed_header_buffer.first, 0);            
            }
        }
        write_byte_bill(Billing::HEADER,
                        true,
                        compressed_header_buffer.size());
    } else {
        always_assert(compressed_header_size == 0 && "Special concatenation requires 0 size header");
    }
    grbs = sizeof(EOI);
    grbgdata = EOI; // if we don't have any garbage, assume FFD9 EOI
    // read header from file
    ReadFull(header_reader, ujpg_mrk, 3 ) ;
    // check marker
    if ( memcmp( ujpg_mrk, "HDR", 3 ) == 0 ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4163,7 +4163,7 @@
                               Sirikata::BrotliCodec::Decompress(compressed_header_buffer.data(),
                                                                 compressed_header_buffer.size(),
                                                                 JpegAllocator<uint8_t>(),
-                                                                max_file_size * 2 + 128 * 1024 * 1024));
+                                                                ((size_t)max_file_size) * 2 + 128 * 1024 * 1024));
                 if (uncompressed_header_buffer.second) {
                     always_assert(false && "Data not properly zlib coded");
                     return false;
```
