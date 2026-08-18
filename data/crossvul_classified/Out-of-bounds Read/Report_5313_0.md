# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5313_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5313_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1319-1359 of the vulnerable file.

                  image->colors=one << bpp;
                  if (!AcquireImageColormap(image,image->colors,exception))
                    goto NoMemory;
                }
              else
                {
                  if(bpp < 24)
                    if( image->colors<(one << bpp) && bpp!=24 )
                      image->colormap=(PixelInfo *) ResizeQuantumMemory(
                       image->colormap,(size_t) (one << bpp),
                       sizeof(*image->colormap));
                }


              switch(Bitmap2Header1.Compression)
                {
                case 0:    /*Uncompressed raster*/
                  {
                    ldblk=(ssize_t) ((bpp*image->columns+7)/8);
                    BImgBuff=(unsigned char *) AcquireQuantumMemory((size_t)
                      ldblk,sizeof(*BImgBuff));
                    if (BImgBuff == (unsigned char *) NULL)
                      goto NoMemory;

                    for(i=0; i< (ssize_t) image->rows; i++)
                      {
                        (void) ReadBlob(image,ldblk,BImgBuff);
                        InsertRow(image,BImgBuff,i,bpp,exception);
                      }

                    if(BImgBuff)
                      BImgBuff=(unsigned char *) RelinquishMagickMemory(BImgBuff);;
                    break;
                  }
                case 1:    /*RLE for WPG2 */
                  {
                    if( UnpackWPG2Raster(image,bpp,exception) < 0)
                      goto DecompressionFailed;
                    break;
                  }   
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1336,7 +1336,7 @@
                   {
                     ldblk=(ssize_t) ((bpp*image->columns+7)/8);
                     BImgBuff=(unsigned char *) AcquireQuantumMemory((size_t)
-                      ldblk,sizeof(*BImgBuff));
+                      ldblk+1,sizeof(*BImgBuff));
                     if (BImgBuff == (unsigned char *) NULL)
                       goto NoMemory;
 
```
