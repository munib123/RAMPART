# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2584_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2584_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 551-591 of the vulnerable file.

          }
        pixel.red=(MagickRealType) ScaleAnyToQuantum((QuantumAny) (red+0.5),
          range);
        pixel.green=(MagickRealType) ScaleAnyToQuantum((QuantumAny) (green+0.5),
          range);
        pixel.blue=(MagickRealType) ScaleAnyToQuantum((QuantumAny) (blue+0.5),
          range);
        pixel.black=(MagickRealType) ScaleAnyToQuantum((QuantumAny) (black+0.5),
          range);
        pixel.alpha=(MagickRealType) ScaleAnyToQuantum((QuantumAny) (alpha+0.5),
          range);
        q=GetAuthenticPixels(image,(ssize_t) x_offset,(ssize_t) y_offset,1,1,
          exception);
        if (q == (Quantum *) NULL)
          continue;
        SetPixelViaPixelInfo(image,&pixel,q);
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
        AcquireNextImage(image_info,image,exception);
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
@@ -568,6 +568,12 @@
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
