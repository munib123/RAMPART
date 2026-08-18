# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 578_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `578_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 2775-2815 of the vulnerable file.

          S.raw_pitch = S.raw_width * 2; // Bayer case, not set before
      }
      else // NO LEGACY FLAG if (decoder_info.decoder_flags & LIBRAW_DECODER_LEGACY)
      {
        if (decoder_info.decoder_flags & LIBRAW_DECODER_ADOBECOPYPIXEL)
        {
          S.raw_pitch = S.raw_width * 8;
        }
        else
        {
          S.iwidth = S.width;
          S.iheight = S.height;
          IO.shrink = 0;
          if (!S.raw_pitch)
            S.raw_pitch =
                (decoder_info.decoder_flags & LIBRAW_DECODER_LEGACY_WITH_MARGINS) ? S.raw_width * 8 : S.width * 8;
        }
        // sRAW and old Foveon decoders only, so extra buffer size is just 1/4
        // allocate image as temporary buffer, size
        imgdata.rawdata.raw_alloc = 0;
        imgdata.image = (ushort(*)[4])calloc(unsigned(S.raw_width) * unsigned(S.raw_height), sizeof(*imgdata.image));
        if (!(decoder_info.decoder_flags & LIBRAW_DECODER_ADOBECOPYPIXEL))
        {
          imgdata.rawdata.raw_image = (ushort *)imgdata.image;
          zero_rawimage = 1;
        }
      }
      ID.input->seek(libraw_internal_data.unpacker_data.data_offset, SEEK_SET);

      unsigned m_save = C.maximum;
      if (load_raw == &LibRaw::unpacked_load_raw && !strcasecmp(imgdata.idata.make, "Nikon"))
        C.maximum = 65535;
      (this->*load_raw)();
      if (zero_rawimage)
        imgdata.rawdata.raw_image = 0;
      if (load_raw == &LibRaw::unpacked_load_raw && !strcasecmp(imgdata.idata.make, "Nikon"))
        C.maximum = m_save;
      if (decoder_info.decoder_flags & LIBRAW_DECODER_OWNALLOC)
      {
        // x3f foveon decoder only: do nothing
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2792,7 +2792,7 @@
         // sRAW and old Foveon decoders only, so extra buffer size is just 1/4
         // allocate image as temporary buffer, size
         imgdata.rawdata.raw_alloc = 0;
-        imgdata.image = (ushort(*)[4])calloc(unsigned(S.raw_width) * unsigned(S.raw_height), sizeof(*imgdata.image));
+        imgdata.image = (ushort(*)[4])calloc(unsigned(MAX(S.width,S.raw_width)) * unsigned(MAX(S.height,S.raw_height)), sizeof(*imgdata.image));
         if (!(decoder_info.decoder_flags & LIBRAW_DECODER_ADOBECOPYPIXEL))
         {
           imgdata.rawdata.raw_image = (ushort *)imgdata.image;
```
