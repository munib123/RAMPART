# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1415_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1415_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1044-1084 of the vulnerable file.

        break;
      p+=strlen(p);
      if ((size_t) (p-sixel_buffer+MagickPathExtent+1) < length)
        continue;
      length<<=1;
      sixel_buffer=(char *) ResizeQuantumMemory(sixel_buffer,length+
        MagickPathExtent+1,sizeof(*sixel_buffer));
      if (sixel_buffer == (char *) NULL)
        break;
      p=sixel_buffer+strlen(sixel_buffer);
    }
  if (sixel_buffer == (char *) NULL)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
  sixel_buffer[length]='\0';
  /*
    Decode SIXEL
  */
  if (sixel_decode(image,(unsigned char *) sixel_buffer,&sixel_pixels,&image->columns,&image->rows,&sixel_palette,&image->colors,exception) == MagickFalse)
    {
      sixel_buffer=(char *) RelinquishMagickMemory(sixel_buffer);
      ThrowReaderException(CorruptImageError,"CorruptImage");
    }
  sixel_buffer=(char *) RelinquishMagickMemory(sixel_buffer);
  image->depth=24;
  image->storage_class=PseudoClass;
  status=SetImageExtent(image,image->columns,image->rows,exception);
  if (status == MagickFalse)
    {
      sixel_pixels=(unsigned char *) RelinquishMagickMemory(sixel_pixels);
      sixel_palette=(unsigned char *) RelinquishMagickMemory(sixel_palette);
      return(DestroyImageList(image));
    }

  if (AcquireImageColormap(image,image->colors, exception) == MagickFalse)
    {
      sixel_pixels=(unsigned char *) RelinquishMagickMemory(sixel_pixels);
      sixel_palette=(unsigned char *) RelinquishMagickMemory(sixel_palette);
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    }
  for (i = 0; i < (ssize_t) image->colors; ++i) {
    image->colormap[i].red   = ScaleCharToQuantum(sixel_palette[i * 4 + 0]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1061,6 +1061,7 @@
   if (sixel_decode(image,(unsigned char *) sixel_buffer,&sixel_pixels,&image->columns,&image->rows,&sixel_palette,&image->colors,exception) == MagickFalse)
     {
       sixel_buffer=(char *) RelinquishMagickMemory(sixel_buffer);
+      sixel_pixels=(unsigned char *) RelinquishMagickMemory(sixel_pixels);
       ThrowReaderException(CorruptImageError,"CorruptImage");
     }
   sixel_buffer=(char *) RelinquishMagickMemory(sixel_buffer);
```
