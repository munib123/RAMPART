# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5303_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5303_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 563-603 of the vulnerable file.

      else if (image->depth > 8)
        return(2);
    }
  else
    if (image->depth > 8)
      return(2);

  return(1);
}

static inline MagickSizeType GetPSDSize(const PSDInfo *psd_info,Image *image)
{
  if (psd_info->version == 1)
    return((MagickSizeType) ReadBlobLong(image));
  return((MagickSizeType) ReadBlobLongLong(image));
}

static inline size_t GetPSDRowSize(Image *image)
{
  if (image->depth == 1)
    return((image->columns+7)/8);
  else
    return(image->columns*GetPSDPacketSize(image));
}

static const char *ModeToString(PSDImageType type)
{
  switch (type)
  {
    case BitmapMode: return "Bitmap";
    case GrayscaleMode: return "Grayscale";
    case IndexedMode: return "Indexed";
    case RGBMode: return "RGB";
    case CMYKMode:  return "CMYK";
    case MultichannelMode: return "Multichannel";
    case DuotoneMode: return "Duotone";
    case LabMode: return "L*A*B";
    default: return "unknown";
  }
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -580,7 +580,7 @@
 static inline size_t GetPSDRowSize(Image *image)
 {
   if (image->depth == 1)
-    return((image->columns+7)/8);
+    return(((image->columns+7)/8)*GetPSDPacketSize(image));
   else
     return(image->columns*GetPSDPacketSize(image));
 }
```
