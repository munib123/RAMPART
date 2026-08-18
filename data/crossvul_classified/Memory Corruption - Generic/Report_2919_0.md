# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2919_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2919_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1051-1091 of the vulnerable file.

              BitmapHeader1.VertRes=ReadBlobLSBShort(image);

              if(BitmapHeader1.HorzRes && BitmapHeader1.VertRes)
                {
                  image->units=PixelsPerCentimeterResolution;
                  image->x_resolution=BitmapHeader1.HorzRes/470.0;
                  image->y_resolution=BitmapHeader1.VertRes/470.0;
                }
              image->columns=BitmapHeader1.Width;
              image->rows=BitmapHeader1.Height;
              bpp=BitmapHeader1.Depth;

              goto UnpackRaster;

            case 0x0E:  /*Color palette */
              WPG_Palette.StartIndex=ReadBlobLSBShort(image);
              WPG_Palette.NumOfEntries=ReadBlobLSBShort(image);
              if ((WPG_Palette.NumOfEntries-WPG_Palette.StartIndex) >
                  (Rec2.RecordLength-2-2) / 3)
                ThrowReaderException(CorruptImageError,"InvalidColormapIndex");
              image->colors=WPG_Palette.NumOfEntries;
              if (!AcquireImageColormap(image,image->colors))
                goto NoMemory;
              for (i=WPG_Palette.StartIndex;
                   i < (int)WPG_Palette.NumOfEntries; i++)
                {
                  image->colormap[i].red=ScaleCharToQuantum((unsigned char)
                    ReadBlobByte(image));
                  image->colormap[i].green=ScaleCharToQuantum((unsigned char)
                    ReadBlobByte(image));
                  image->colormap[i].blue=ScaleCharToQuantum((unsigned char)
                    ReadBlobByte(image));
                }
              break;

            case 0x11:  /* Start PS l1 */
              if(Rec.RecordLength > 8)
                image=ExtractPostscript(image,image_info,
                  TellBlob(image)+8,   /* skip PS header in the wpg */
                  (ssize_t) Rec.RecordLength-8,exception);
              break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1068,6 +1068,8 @@
               if ((WPG_Palette.NumOfEntries-WPG_Palette.StartIndex) >
                   (Rec2.RecordLength-2-2) / 3)
                 ThrowReaderException(CorruptImageError,"InvalidColormapIndex");
+              if (WPG_Palette.StartIndex > WPG_Palette.NumOfEntries)
+                ThrowReaderException(CorruptImageError,"InvalidColormapIndex");
               image->colors=WPG_Palette.NumOfEntries;
               if (!AcquireImageColormap(image,image->colors))
                 goto NoMemory;
```
