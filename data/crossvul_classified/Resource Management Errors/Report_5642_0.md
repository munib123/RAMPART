# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 5642_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5642_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 1127-1168 of the vulnerable file.

            ID.input->seek(spos,SEEK_SET);
          }
#endif
        if(!imgdata.rawdata.raw_image && !imgdata.rawdata.color4_image && !imgdata.rawdata.color3_image) // RawSpeed failed!
          {
            // Not allocated on RawSpeed call, try call LibRaw
            if(decoder_info.decoder_flags &  LIBRAW_DECODER_FLATFIELD)
              {
                imgdata.rawdata.raw_alloc = malloc(rwidth*(rheight+7)*sizeof(imgdata.rawdata.raw_image[0]));
                imgdata.rawdata.raw_image = (ushort*) imgdata.rawdata.raw_alloc;
              }
            else if (decoder_info.decoder_flags & LIBRAW_DECODER_LEGACY)
              {
                // sRAW and Foveon only, so extra buffer size is just 1/4
                // Legacy converters does not supports half mode!
                S.iwidth = S.width;
                S.iheight= S.height;
                IO.shrink = 0;
				S.raw_pitch = S.width*8;
                // allocate image as temporary buffer, size 
                imgdata.rawdata.raw_alloc = calloc(S.iwidth*S.iheight,sizeof(*imgdata.image));
                imgdata.image = (ushort (*)[4]) imgdata.rawdata.raw_alloc;
              }
            ID.input->seek(libraw_internal_data.unpacker_data.data_offset, SEEK_SET);

			unsigned m_save = C.maximum;
			if(load_raw == &LibRaw::unpacked_load_raw && !strcasecmp(imgdata.idata.make,"Nikon"))
				C.maximum=65535;
            (this->*load_raw)();
			if(load_raw == &LibRaw::unpacked_load_raw && !strcasecmp(imgdata.idata.make,"Nikon"))
				C.maximum = m_save;
          }

        if(imgdata.rawdata.raw_image)
          crop_masked_pixels(); // calculate black levels

        // recover saved
        if( (decoder_info.decoder_flags & LIBRAW_DECODER_LEGACY) && !imgdata.rawdata.color4_image)
            {
                imgdata.image = 0; 
                imgdata.rawdata.color4_image = (ushort (*)[4]) imgdata.rawdata.raw_alloc;
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1144,8 +1144,8 @@
                 IO.shrink = 0;
 				S.raw_pitch = S.width*8;
                 // allocate image as temporary buffer, size 
-                imgdata.rawdata.raw_alloc = calloc(S.iwidth*S.iheight,sizeof(*imgdata.image));
-                imgdata.image = (ushort (*)[4]) imgdata.rawdata.raw_alloc;
+                imgdata.rawdata.raw_alloc = 0;
+                imgdata.image = (ushort (*)[4]) calloc(S.iwidth*S.iheight,sizeof(*imgdata.image));
               }
             ID.input->seek(libraw_internal_data.unpacker_data.data_offset, SEEK_SET);
 
@@ -1155,6 +1155,12 @@
             (this->*load_raw)();
 			if(load_raw == &LibRaw::unpacked_load_raw && !strcasecmp(imgdata.idata.make,"Nikon"))
 				C.maximum = m_save;
+			if (decoder_info.decoder_flags & LIBRAW_DECODER_LEGACY)
+			{
+				// successfully decoded legacy image, attach image to raw_alloc
+				imgdata.rawdata.raw_alloc = imgdata.image;
+				imgdata.image = 0; 
+			}
           }
 
         if(imgdata.rawdata.raw_image)
```
