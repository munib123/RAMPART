# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 363_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `363_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 81-122 of the vulnerable file.

} CUTHeader;

typedef struct
{
  char FileId[2];
  unsigned Version;
  unsigned Size;
  char FileType;
  char SubType;
  unsigned BoardID;
  unsigned GraphicsMode;
  unsigned MaxIndex;
  unsigned MaxRed;
  unsigned MaxGreen;
  unsigned MaxBlue;
  char PaletteId[20];
} CUTPalHeader;



static void InsertRow(Image *image,ssize_t depth,unsigned char *p,ssize_t y,
  ExceptionInfo *exception)
{
  size_t bit; ssize_t x;
  register Quantum *q;
  Quantum index;

  index=0;
  switch (depth)
  {
    case 1:  /* Convert bitmap scanline. */
      {
        q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
        if (q == (Quantum *) NULL)
          break;
        for (x=0; x < ((ssize_t) image->columns-7); x+=8)
        {
          for (bit=0; bit < 8; bit++)
          {
            index=(Quantum) ((((*p) & (0x80 >> bit)) != 0) ? 0x01 : 0x00);
            SetPixelIndex(image,index,q);
            q+=GetPixelChannels(image);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,132 +98,165 @@
 
 
 
-static void InsertRow(Image *image,ssize_t depth,unsigned char *p,ssize_t y,
-  ExceptionInfo *exception)
+static MagickBooleanType InsertRow(Image *image,ssize_t bpp,unsigned char *p,
+  ssize_t y,ExceptionInfo *exception)
 {
-  size_t bit; ssize_t x;
-  register Quantum *q;
-  Quantum index;
-
-  index=0;
-  switch (depth)
-  {
+  int
+    bit;
+
+  Quantum
+    index;
+
+  register Quantum
+    *q;
+
+  ssize_t
+    x;
+
+  q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
+  if (q == (Quantum *) NULL)
+    return(MagickFalse);
+  switch (bpp)
+    {
     case 1:  /* Convert bitmap scanline. */
       {
-        q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
-        if (q == (Quantum *) NULL)
-          break;
         for (x=0; x < ((ssize_t) image->columns-7); x+=8)
         {
           for (bit=0; bit < 8; bit++)
           {
-            index=(Quantum) ((((*p) & (0x80 >> bit)) != 0) ? 0x01 : 0x00);
-            SetPixelIndex(image,index,q);
+            index=((*p) & (0x80 >> bit) ? 0x01 : 0x00);
+            SetPixelIndex(image,index,q);
+            if (index < image->colors)
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
             q+=GetPixelChannels(image);
           }
           p++;
         }
         if ((image->columns % 8) != 0)
           {
-            for (bit=0; bit < (image->columns % 8); bit++)
-              {
-                index=(Quantum) ((((*p) & (0x80 >> bit)) != 0) ? 0x01 : 0x00);
-                SetPixelIndex(image,index,q);
-                q+=GetPixelChannels(image);
-              }
+            for (bit=0; bit < (ssize_t) (image->columns % 8); bit++)
+            {
+              index=((*p) & (0x80 >> bit) ? 0x01 : 0x00);
+              SetPixelIndex(image,index,q);
+              if (index < image->colors)
+                SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
+              q+=GetPixelChannels(image);
+            }
             p++;
           }
-        (void) SyncAuthenticPixels(image,exception);
         break;
       }
     case 2:  /* Convert PseudoColor scanline. */
       {
-        q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
-        if (q == (Quantum *) NULL)
-          break;
-        for (x=0; x < ((ssize_t) image->columns-1); x+=2)
-        {
-          index=ConstrainColormapIndex(image,(*p >> 6) & 0x3,exception);
-          SetPixelIndex(image,index,q);
-          q+=GetPixelChannels(image);
-          index=ConstrainColormapIndex(image,(*p >> 4) & 0x3,exception);
-          SetPixelIndex(image,index,q);
-          q+=GetPixelChannels(image);
-          index=ConstrainColormapIndex(image,(*p >> 2) & 0x3,exception);
-          SetPixelIndex(image,index,q);
-          q+=GetPixelChannels(image);
-          index=ConstrainColormapIndex(image,(*p) & 0x3,exception);
-          SetPixelIndex(image,index,q);
-          q+=GetPixelChannels(image);
-          p++;
-        }
-        if ((image->columns % 4) != 0)
+        for (x=0; x < ((ssize_t) image->columns-3); x+=4)
+        {
+            index=ConstrainColormapIndex(image,(*p >> 6) & 0x3,exception);
+            SetPixelIndex(image,index,q);
+            if (index < image->colors)
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
+            q+=GetPixelChannels(image);
+            index=ConstrainColormapIndex(image,(*p >> 4) & 0x3,exception);
+            SetPixelIndex(image,index,q);
+            if (index < image->colors)
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
+            q+=GetPixelChannels(image);
+            index=ConstrainColormapIndex(image,(*p >> 2) & 0x3,exception);
+            SetPixelIndex(image,index,q);
+            if (index < image->colors)
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
+            q+=GetPixelChannels(image);
+            index=ConstrainColormapIndex(image,(*p) & 0x3,exception);
+            SetPixelIndex(image,index,q);
+            if (index < image->colors)
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
+            q+=GetPixelChannels(image);
+            p++;
+        }
+       if ((image->columns % 4) != 0)
           {
             index=ConstrainColormapIndex(image,(*p >> 6) & 0x3,exception);
             SetPixelIndex(image,index,q);
-            q+=GetPixelChannels(image);
-            if ((image->columns % 4) >= 1)
-
+            if (index < image->colors)
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
+            q+=GetPixelChannels(image);
+            if ((image->columns % 4) > 1)
               {
                 index=ConstrainColormapIndex(image,(*p >> 4) & 0x3,exception);
                 SetPixelIndex(image,index,q);
+                if (index < image->colors)
+                  SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
                 q+=GetPixelChannels(image);
-                if ((image->columns % 4) >= 2)
-
+                if ((image->columns % 4) > 2)
                   {
                     index=ConstrainColormapIndex(image,(*p >> 2) & 0x3,
                       exception);
                     SetPixelIndex(image,index,q);
+                    if (index < image->colors)
+                      SetPixelViaPixelInfo(image,image->colormap+(ssize_t)
+                        index,q);
                     q+=GetPixelChannels(image);
                   }
               }
             p++;
           }
-        (void) SyncAuthenticPixels(image,exception);
         break;
       }
 
     case 4:  /* Convert PseudoColor scanline. */
       {
-        q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
-        if (q == (Quantum *) NULL)
-          break;
         for (x=0; x < ((ssize_t) image->columns-1); x+=2)
-        {
-            index=ConstrainColormapIndex(image,(*p >> 4) & 0xf,exception);
-            SetPixelIndex(image,index,q);
-            q+=GetPixelChannels(image);
-            index=ConstrainColormapIndex(image,(*p) & 0xf,exception);
-            SetPixelIndex(image,index,q);
-            q+=GetPixelChannels(image);
+          {
+            index=ConstrainColormapIndex(image,(*p >> 4) & 0x0f,exception);
+            SetPixelIndex(image,index,q);
+            if (index < image->colors)
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
+            q+=GetPixelChannels(image);
+            index=ConstrainColormapIndex(image,(*p) & 0x0f,exception);
+            SetPixelIndex(image,index,q);
+            if (index < image->colors)
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
             p++;
+            q+=GetPixelChannels(image);
           }
         if ((image->columns % 2) != 0)
           {
-            index=ConstrainColormapIndex(image,(*p >> 4) & 0xf,exception);
-            SetPixelIndex(image,index,q);
-            q+=GetPixelChannels(image);
+            index=ConstrainColormapIndex(image,(*p >> 4) & 0x0f,exception);
+            SetPixelIndex(image,index,q);
+            if (index < image->colors)
+              SetPixelViaPixelInfo(image,image->colormap+(ssize_t) index,q);
             p++;
+            q+=GetPixelChannels(image);
           }
-        (void) SyncAuthenticPixels(image,exception);
         break;
       }
     case 8: /* Convert PseudoColor scanline. */
       {
-        q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
-        if (q == (Quantum *) NULL)
-          break;
         for (x=0; x < (ssize_t) image->columns; x++)
-        {
-          index=ConstrainColormapIndex(image,*p,exception);
-          SetPixelIndex(image,index,q);
-          p++;
+          {
+            index=ConstrainColormapIndex(image,*p,exception);
... (diff truncated)
```
