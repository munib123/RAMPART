# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3109_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3109_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1657-1697 of the vulnerable file.

                if (image->debug != MagickFalse)
                  (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                    "      layer blending ranges: length=%.20g",(double)
                    ((MagickOffsetType) length));
                /*
                  We read it, but don't use it...
                */
                for (j=0; j < (ssize_t) length; j+=8)
                {
                  size_t blend_source=ReadBlobLong(image);
                  size_t blend_dest=ReadBlobLong(image);
                  if (image->debug != MagickFalse)
                    (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                      "        source(%x), dest(%x)",(unsigned int)
                      blend_source,(unsigned int) blend_dest);
                }
              }
            /*
              Layer name.
            */
            length=(MagickSizeType) ReadBlobByte(image);
            combined_length+=length+1;
            if (length > 0)
              (void) ReadBlob(image,(size_t) length++,layer_info[i].name);
            layer_info[i].name[length]='\0';
            if (image->debug != MagickFalse)
              (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                "      layer name: %s",layer_info[i].name);
            if ((length % 4) != 0)
              {
                length=4-(length % 4);
                combined_length+=length;
                /* Skip over the padding of the layer name */
                if (DiscardBlobBytes(image,length) == MagickFalse)
                  {
                    layer_info=DestroyLayerInfo(layer_info,number_layers);
                    ThrowBinaryException(CorruptImageError,
                      "UnexpectedEndOfFile",image->filename);
                  }
              }
            length=(MagickSizeType) size-combined_length;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1674,7 +1674,7 @@
             /*
               Layer name.
             */
-            length=(MagickSizeType) ReadBlobByte(image);
+            length=(MagickSizeType) (unsigned char) ReadBlobByte(image);
             combined_length+=length+1;
             if (length > 0)
               (void) ReadBlob(image,(size_t) length++,layer_info[i].name);
```
