# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 4780_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4780_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1705-1745 of the vulnerable file.

            if (length > 0)
              {
                unsigned char
                  *info;

                layer_info[i].info=AcquireStringInfo((const size_t) length);
                info=GetStringInfoDatum(layer_info[i].info);
                (void) ReadBlob(image,(const size_t) length,info);
              }
          }
      }

      for (i=0; i < number_layers; i++)
      {
        if ((layer_info[i].page.width == 0) ||
              (layer_info[i].page.height == 0))
          {
            if (image->debug != MagickFalse)
              (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                "      layer data is empty");
            continue;
          }

        /*
          Allocate layered image.
        */
        layer_info[i].image=CloneImage(image,layer_info[i].page.width,
          layer_info[i].page.height,MagickFalse,exception);
        if (layer_info[i].image == (Image *) NULL)
          {
            layer_info=DestroyLayerInfo(layer_info,number_layers);
            if (image->debug != MagickFalse)
              (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                "  allocation of image for layer %.20g failed",(double) i);
            ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
              image->filename);
          }

        if (layer_info[i].info != (StringInfo *) NULL)
          {
            (void) SetImageProfile(layer_info[i].image,"psd:additional-info",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1722,6 +1722,8 @@
             if (image->debug != MagickFalse)
               (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                 "      layer data is empty");
+            if (layer_info[i].info != (StringInfo *) NULL)
+              layer_info[i].info=DestroyStringInfo(layer_info[i].info);
             continue;
           }
 
```
