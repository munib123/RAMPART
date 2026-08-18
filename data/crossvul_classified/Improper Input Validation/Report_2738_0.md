# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2738_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2738_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 380-420 of the vulnerable file.

    if (image->ping == MagickFalse)
      {
        jp2_status=opj_decode(jp2_codec,jp2_stream,jp2_image);
        if (jp2_status != 0)
          jp2_status=opj_end_decompress(jp2_codec,jp2_stream);
      }
  if (jp2_status == 0)
    {
      opj_stream_destroy(jp2_stream);
      opj_destroy_codec(jp2_codec);
      opj_image_destroy(jp2_image);
      ThrowReaderException(DelegateError,"UnableToDecodeImageFile");
    }
  opj_stream_destroy(jp2_stream);
  for (i=0; i < (ssize_t) jp2_image->numcomps; i++)
  {
    if ((jp2_image->comps[0].dx == 0) || (jp2_image->comps[0].dy == 0) ||
        (jp2_image->comps[0].dx != jp2_image->comps[i].dx) ||
        (jp2_image->comps[0].dy != jp2_image->comps[i].dy) ||
        (jp2_image->comps[0].prec != jp2_image->comps[i].prec) ||
        (jp2_image->comps[0].sgnd != jp2_image->comps[i].sgnd))
      {
        opj_destroy_codec(jp2_codec);
        opj_image_destroy(jp2_image);
        ThrowReaderException(CoderError,"IrregularChannelGeometryNotSupported")
      }
  }
  /*
    Convert JP2 image.
  */
  image->columns=(size_t) jp2_image->comps[0].w;
  image->rows=(size_t) jp2_image->comps[0].h;
  image->depth=jp2_image->comps[0].prec;
  status=SetImageExtent(image,image->columns,image->rows);
  if (status == MagickFalse)
    {
      InheritException(exception,&image->exception);
      return(DestroyImageList(image));
    }
  image->compression=JPEG2000Compression;
  if (jp2_image->color_space == 2)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -397,7 +397,8 @@
         (jp2_image->comps[0].dx != jp2_image->comps[i].dx) ||
         (jp2_image->comps[0].dy != jp2_image->comps[i].dy) ||
         (jp2_image->comps[0].prec != jp2_image->comps[i].prec) ||
-        (jp2_image->comps[0].sgnd != jp2_image->comps[i].sgnd))
+        (jp2_image->comps[0].sgnd != jp2_image->comps[i].sgnd) ||
+        (jp2_image->comps[i].data == NULL))
       {
         opj_destroy_codec(jp2_codec);
         opj_image_destroy(jp2_image);
```
