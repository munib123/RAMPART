# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2784_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2784_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 1674-1714 of the vulnerable file.

                  }
              }
            length=ReadBlobLong(image);
            combined_length+=length+4;
            if (length != 0)
              {
                /*
                  Layer blending ranges info.
                */
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
            length=(MagickSizeType) (unsigned char) ReadBlobByte(image);
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1691,6 +1691,12 @@
                 {
                   size_t blend_source=ReadBlobLong(image);
                   size_t blend_dest=ReadBlobLong(image);
+                  if (EOFBlob(image) != MagickFalse)
+                    {
+                      layer_info=DestroyLayerInfo(layer_info,number_layers);
+                      ThrowBinaryException(CorruptImageError,
+                        "InsufficientImageDataInFile",image->filename);
+                    }
                   if (image->debug != MagickFalse)
                     (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                       "        source(%x), dest(%x)",(unsigned int)
```
