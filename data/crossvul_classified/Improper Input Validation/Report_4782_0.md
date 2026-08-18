# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4782_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4782_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 624-664 of the vulnerable file.

    "The latter two forms do not require the path to the command hard coded.\n",
    "Note: \"magick-script\" needs to be linked to the \"magick\" command.\n",
    "\n",
    "For more information on usage, options, examples, and techniques\n",
    "see the ImageMagick website at    ", MagickAuthoritativeURL);

  return;
}

/*
   Concatanate given file arguments to the given output argument.
   Used for a special -concatenate option used for specific 'delegates'.
   The option is not formally documented.

      magick -concatenate files... output

   This is much like the UNIX "cat" command, but for both UNIX and Windows,
   however the last argument provides the output filename.
*/
static MagickBooleanType ConcatenateImages(int argc,char **argv,
     ExceptionInfo *exception )
{
  FILE
    *input,
    *output;

  int
    c;

  register ssize_t
    i;

  if (ExpandFilenames(&argc,&argv) == MagickFalse)
    ThrowFileException(exception,ResourceLimitError,"MemoryAllocationFailed",
         GetExceptionMessage(errno));

  output=fopen_utf8(argv[argc-1],"wb");
  if (output == (FILE *) NULL) {
    ThrowFileException(exception,FileOpenError,"UnableToOpenFile",argv[argc-1]);
    return(MagickFalse);
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -641,12 +641,15 @@
    however the last argument provides the output filename.
 */
 static MagickBooleanType ConcatenateImages(int argc,char **argv,
-     ExceptionInfo *exception )
+  ExceptionInfo *exception )
 {
   FILE
     *input,
     *output;
 
+  MagickBooleanType
+    status;
+
   int
     c;
 
@@ -655,29 +658,31 @@
 
   if (ExpandFilenames(&argc,&argv) == MagickFalse)
     ThrowFileException(exception,ResourceLimitError,"MemoryAllocationFailed",
-         GetExceptionMessage(errno));
-
+      GetExceptionMessage(errno));
   output=fopen_utf8(argv[argc-1],"wb");
-  if (output == (FILE *) NULL) {
-    ThrowFileException(exception,FileOpenError,"UnableToOpenFile",argv[argc-1]);
-    return(MagickFalse);
-  }
-  for (i=2; i < (ssize_t) (argc-1); i++) {
-#if 0
-    fprintf(stderr, "DEBUG: Concatenate Image: \"%s\"\n", argv[i]);
-#endif
+  if (output == (FILE *) NULL)
+    {
+      ThrowFileException(exception,FileOpenError,"UnableToOpenFile",
+        argv[argc-1]);
+      return(MagickFalse);
+    }
+  status=MagickTrue;
+  for (i=2; i < (ssize_t) (argc-1); i++)
+  {
     input=fopen_utf8(argv[i],"rb");
-    if (input == (FILE *) NULL) {
+    if (input == (FILE *) NULL)
+      {
         ThrowFileException(exception,FileOpenError,"UnableToOpenFile",argv[i]);
         continue;
       }
     for (c=fgetc(input); c != EOF; c=fgetc(input))
-      (void) fputc((char) c,output);
+      if (fputc((char) c,output) != c)
+        status=MagickFalse;
     (void) fclose(input);
     (void) remove_utf8(argv[i]);
   }
   (void) fclose(output);
-  return(MagickTrue);
+  return(status);
 }
 
 WandExport MagickBooleanType MagickImageCommand(ImageInfo *image_info,int argc,
```
