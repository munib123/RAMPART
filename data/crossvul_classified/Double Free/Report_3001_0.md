# CrossVul Fix Pair: Double Free in c
**Pair ID:** 3001_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3001_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 883-923 of the vulnerable file.


 done:

  /* Move comments and extensions after last image into stream. */
  if (gfs && gfi) {
      Gif_Extension* gfex;
      gfs->end_comment = gfi->comment;
      gfi->comment = 0;
      gfs->end_extension_list = gfi->extension_list;
      gfi->extension_list = 0;
      for (gfex = gfs->end_extension_list; gfex; gfex = gfex->next)
          gfex->image = NULL;
  }

  Gif_DeleteImage(gfi);
  Gif_DeleteArray(last_name);
  Gif_DeleteArray(gfc.prefix);
  Gif_DeleteArray(gfc.suffix);
  Gif_DeleteArray(gfc.length);
  gfc.gfi = 0;

  if (gfs)
    gfs->errors = gfc.errors[1];
  if (gfs && gfc.errors[1] == 0
      && !(read_flags & GIF_READ_TRAILING_GARBAGE_OK)
      && !grr->eofer(grr))
      gif_read_error(&gfc, 0, "trailing garbage after GIF ignored");
  /* finally, export last message */
  gif_read_error(&gfc, -1, 0);

  return gfs;
}


Gif_Stream *
Gif_FullReadFile(FILE *f, int read_flags,
		 const char* landmark, Gif_ReadErrorHandler h)
{
  Gif_Reader grr;
  if (!f) return 0;
  grr.f = f;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -900,6 +900,7 @@
   Gif_DeleteArray(gfc.suffix);
   Gif_DeleteArray(gfc.length);
   gfc.gfi = 0;
+  last_name = 0;
 
   if (gfs)
     gfs->errors = gfc.errors[1];
```
