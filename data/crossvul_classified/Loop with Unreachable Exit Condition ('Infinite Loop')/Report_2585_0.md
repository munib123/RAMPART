# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2585_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2585_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 568-608 of the vulnerable file.

        pixel.opacity=(MagickRealType) ScaleAnyToQuantum((QuantumAny) (opacity+
          0.5),range);
        q=GetAuthenticPixels(image,(ssize_t) x_offset,(ssize_t) y_offset,1,1,
          exception);
        if (q == (PixelPacket *) NULL)
          continue;
        SetPixelRed(q,pixel.red);
        SetPixelGreen(q,pixel.green);
        SetPixelBlue(q,pixel.blue);
        if (image->colorspace == CMYKColorspace)
          {
            indexes=GetAuthenticIndexQueue(image);
            SetPixelIndex(indexes,pixel.index);
          }
        if (image->matte != MagickFalse)
          SetPixelAlpha(q,pixel.opacity);
        if (SyncAuthenticPixels(image,exception) == MagickFalse)
          break;
      }
    }
    (void) ReadBlobString(image,text);
    if (LocaleNCompare((char *) text,MagickID,strlen(MagickID)) == 0)
      {
        /*
          Allocate next image structure.
        */
        AcquireNextImage(image_info,image);
        if (GetNextImageInList(image) == (Image *) NULL)
          {
            image=DestroyImageList(image);
            return((Image *) NULL);
          }
        image=SyncNextImageInList(image);
        status=SetImageProgress(image,LoadImagesTag,TellBlob(image),
          GetBlobSize(image));
        if (status == MagickFalse)
          break;
      }
  } while (LocaleNCompare((char *) text,MagickID,strlen(MagickID)) == 0);
  (void) CloseBlob(image);
  return(GetFirstImageInList(image));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -585,6 +585,12 @@
           break;
       }
     }
+    if (EOFBlob(image) != MagickFalse)
+      {
+        ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
+          image->filename);
+        break;
+      }
     (void) ReadBlobString(image,text);
     if (LocaleNCompare((char *) text,MagickID,strlen(MagickID)) == 0)
       {
```
