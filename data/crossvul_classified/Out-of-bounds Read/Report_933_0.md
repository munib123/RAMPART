# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 933_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `933_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 639-679 of the vulnerable file.

        p=GetCacheViewVirtualPixels(source_view,0,y,source_image->columns,1,
          exception);
        q=GetCacheViewAuthenticPixels(image_view,x_offset,y+y_offset,
          source_image->columns,1,exception);
        if ((p == (const Quantum *) NULL) || (q == (Quantum *) NULL))
          {
            status=MagickFalse;
            continue;
          }
        for (x=0; x < (ssize_t) source_image->columns; x++)
        {
          register ssize_t
            i;

          if (GetPixelReadMask(source_image,p) <= (QuantumRange/2))
            {
              p+=GetPixelChannels(source_image);
              q+=GetPixelChannels(image);
              continue;
            }
          for (i=0; i < (ssize_t) GetPixelChannels(image); i++)
          {
            PixelChannel channel = GetPixelChannelChannel(image,i);
            PixelTrait traits = GetPixelChannelTraits(image,channel);
            PixelTrait source_traits=GetPixelChannelTraits(source_image,
              channel);
            if (traits == UndefinedPixelTrait)
              continue;
            if (source_traits != UndefinedPixelTrait)
              SetPixelChannel(image,channel,p[i],q);
            else if (channel == AlphaPixelChannel)
              SetPixelChannel(image,channel,OpaqueAlpha,q);
          }
          p+=GetPixelChannels(source_image);
          q+=GetPixelChannels(image);
        }
        sync=SyncCacheViewAuthenticPixels(image_view,exception);
        if (sync == MagickFalse)
          status=MagickFalse;
        if (image->progress_monitor != (MagickProgressMonitor) NULL)
          {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -656,18 +656,19 @@
               q+=GetPixelChannels(image);
               continue;
             }
-          for (i=0; i < (ssize_t) GetPixelChannels(image); i++)
-          {
-            PixelChannel channel = GetPixelChannelChannel(image,i);
+          for (i=0; i < (ssize_t) GetPixelChannels(source_image); i++)
+          {
+            PixelChannel channel = GetPixelChannelChannel(source_image,i);
+            PixelTrait source_traits = GetPixelChannelTraits(source_image,
+              channel);
             PixelTrait traits = GetPixelChannelTraits(image,channel);
-            PixelTrait source_traits=GetPixelChannelTraits(source_image,
-              channel);
-            if (traits == UndefinedPixelTrait)
+            if (source_traits == UndefinedPixelTrait)
               continue;
-            if (source_traits != UndefinedPixelTrait)
+            if (traits != UndefinedPixelTrait)
               SetPixelChannel(image,channel,p[i],q);
-            else if (channel == AlphaPixelChannel)
-              SetPixelChannel(image,channel,OpaqueAlpha,q);
+            else
+              if (channel == AlphaPixelChannel)
+                SetPixelChannel(image,channel,OpaqueAlpha,q);
           }
           p+=GetPixelChannels(source_image);
           q+=GetPixelChannels(image);
```
