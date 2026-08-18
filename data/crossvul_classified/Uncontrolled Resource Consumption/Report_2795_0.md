# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 2795_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2795_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1033-1073 of the vulnerable file.

  image->columns = 1;
  image->rows = 1;
  image->colors = 0;
  bpp=0;
  BitmapHeader2.RotAngle=0;
  Rec2.RecordLength = 0;

  switch(Header.FileType)
    {
    case 1:     /* WPG level 1 */
      while(!EOFBlob(image)) /* object parser loop */
        {
          (void) SeekBlob(image,Header.DataOffset,SEEK_SET);
          if(EOFBlob(image))
            break;

          Rec.RecType=(i=ReadBlobByte(image));
          if(i==EOF)
            break;
          Rd_WP_DWORD(image,&Rec.RecordLength);
          if(EOFBlob(image))
            break;

          Header.DataOffset=TellBlob(image)+Rec.RecordLength;

          switch(Rec.RecType)
            {
            case 0x0B: /* bitmap type 1 */
              BitmapHeader1.Width=ReadBlobLSBShort(image);
              BitmapHeader1.Height=ReadBlobLSBShort(image);
              if ((BitmapHeader1.Width == 0) || (BitmapHeader1.Height == 0))
                ThrowReaderException(CorruptImageError,"ImproperImageHeader");
              BitmapHeader1.Depth=ReadBlobLSBShort(image);
              BitmapHeader1.HorzRes=ReadBlobLSBShort(image);
              BitmapHeader1.VertRes=ReadBlobLSBShort(image);

              if(BitmapHeader1.HorzRes && BitmapHeader1.VertRes)
                {
                  image->units=PixelsPerCentimeterResolution;
                  image->x_resolution=BitmapHeader1.HorzRes/470.0;
                  image->y_resolution=BitmapHeader1.VertRes/470.0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1050,6 +1050,8 @@
           if(i==EOF)
             break;
           Rd_WP_DWORD(image,&Rec.RecordLength);
+          if (Rec.RecordLength > GetBlobSize(image))
+            ThrowReaderException(CorruptImageError,"ImproperImageHeader");
           if(EOFBlob(image))
             break;
 
```
