# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5304_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5304_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 312-352 of the vulnerable file.

          {
            for (bit=0; bit < (ssize_t) (image->columns % 8); bit++)
              {
                index=((*p) & (0x80 >> bit) ? 0x01 : 0x00);
                SetPixelIndex(indexes+x+bit,index);
                SetPixelRGBO(q,image->colormap+(ssize_t) index);
                q++;
              }
            p++;
          }
        if (!SyncAuthenticPixels(image,exception))
          break;
        break;
      }
    case 2:  /* Convert PseudoColor scanline. */
      {
        q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
        if (q == (PixelPacket *) NULL)
          break;
        indexes=GetAuthenticIndexQueue(image);
        for (x=0; x < ((ssize_t) image->columns-1); x+=2)
        {
            index=ConstrainColormapIndex(image,(*p >> 6) & 0x3);
            SetPixelIndex(indexes+x,index);
            SetPixelRGBO(q,image->colormap+(ssize_t) index);
            q++;
            index=ConstrainColormapIndex(image,(*p >> 4) & 0x3);
            SetPixelIndex(indexes+x,index);
            SetPixelRGBO(q,image->colormap+(ssize_t) index);
            q++;
            index=ConstrainColormapIndex(image,(*p >> 2) & 0x3);
            SetPixelIndex(indexes+x,index);
            SetPixelRGBO(q,image->colormap+(ssize_t) index);
            q++;
            index=ConstrainColormapIndex(image,(*p) & 0x3);
            SetPixelIndex(indexes+x+1,index);
            SetPixelRGBO(q,image->colormap+(ssize_t) index);
            p++;
            q++;
        }
       if ((image->columns % 4) != 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -329,7 +329,7 @@
         if (q == (PixelPacket *) NULL)
           break;
         indexes=GetAuthenticIndexQueue(image);
-        for (x=0; x < ((ssize_t) image->columns-1); x+=2)
+        for (x=0; x < ((ssize_t) image->columns-1); x+=4)
         {
             index=ConstrainColormapIndex(image,(*p >> 6) & 0x3);
             SetPixelIndex(indexes+x,index);
```
