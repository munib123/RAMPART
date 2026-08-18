# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 908_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `908_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 244-284 of the vulnerable file.


static MagickOffsetType TIFFSeekCustomStream(const MagickOffsetType offset,
  const int whence,void *user_data)
{
  PhotoshopProfile
    *profile;

  profile=(PhotoshopProfile *) user_data;
  switch (whence)
  {
    case SEEK_SET:
    default:
    {
      if (offset < 0)
        return(-1);
      profile->offset=offset;
      break;
    }
    case SEEK_CUR:
    {
      if ((profile->offset+offset) < 0)
        return(-1);
      profile->offset+=offset;
      break;
    }
    case SEEK_END:
    {
      if (((MagickOffsetType) profile->length+offset) < 0)
        return(-1);
      profile->offset=profile->length+offset;
      break;
    }
  }

  return(profile->offset);
}

static MagickOffsetType TIFFTellCustomStream(void *user_data)
{
  PhotoshopProfile
    *profile;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -261,6 +261,12 @@
     }
     case SEEK_CUR:
     {
+      if (((offset > 0) && (profile->offset > (SSIZE_MAX-offset))) ||
+          ((offset < 0) && (profile->offset < (-SSIZE_MAX-offset))))
+        {
+          errno=EOVERFLOW;
+          return(-1);
+        }
       if ((profile->offset+offset) < 0)
         return(-1);
       profile->offset+=offset;
```
