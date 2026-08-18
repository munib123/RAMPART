# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2576_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2576_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 996-1036 of the vulnerable file.

%  RegisterMPCImage() adds properties for the Cache image format to
%  the list of supported formats.  The properties include the image format
%  tag, a method to read and/or write the format, whether the format
%  supports the saving of more than one frame to the same file or blob,
%  whether the format supports native in-memory I/O, and a brief
%  description of the format.
%
%  The format of the RegisterMPCImage method is:
%
%      size_t RegisterMPCImage(void)
%
*/
ModuleExport size_t RegisterMPCImage(void)
{
  MagickInfo
    *entry;

  entry=SetMagickInfo("CACHE");
  entry->description=ConstantString("Magick Persistent Cache image format");
  entry->module=ConstantString("MPC");
  entry->seekable_stream=MagickTrue;
  entry->stealth=MagickTrue;
  (void) RegisterMagickInfo(entry);
  entry=SetMagickInfo("MPC");
  entry->decoder=(DecodeImageHandler *) ReadMPCImage;
  entry->encoder=(EncodeImageHandler *) WriteMPCImage;
  entry->magick=(IsImageFormatHandler *) IsMPC;
  entry->description=ConstantString("Magick Persistent Cache image format");
  entry->seekable_stream=MagickTrue;
  entry->module=ConstantString("MPC");
  (void) RegisterMagickInfo(entry);
  return(MagickImageCoderSignature);
}


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   U n r e g i s t e r M P C I m a g e                                       %
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1013,7 +1013,6 @@
   entry=SetMagickInfo("CACHE");
   entry->description=ConstantString("Magick Persistent Cache image format");
   entry->module=ConstantString("MPC");
-  entry->seekable_stream=MagickTrue;
   entry->stealth=MagickTrue;
   (void) RegisterMagickInfo(entry);
   entry=SetMagickInfo("MPC");
```
