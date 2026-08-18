# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 3397_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3397_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 555-595 of the vulnerable file.

                  }
                if (LocaleCompare(keyword,"montage") == 0)
                  {
                    (void) CloneString(&image->montage,options);
                    break;
                  }
                (void) SetImageProperty(image,keyword,options,exception);
                break;
              }
              case 'n':
              case 'N':
              {
                if (LocaleCompare(keyword,"number-channels") == 0)
                  {
                    image->number_channels=StringToUnsignedLong(options);
                    break;
                  }
                if (LocaleCompare(keyword,"number-meta-channels") == 0)
                  {
                    image->number_meta_channels=StringToUnsignedLong(options);
                    break;
                  }
                break;
              }
              case 'o':
              case 'O':
              {
                if (LocaleCompare(keyword,"orientation") == 0)
                  {
                    ssize_t
                      orientation;

                    orientation=ParseCommandOption(MagickOrientationOptions,
                      MagickFalse,options);
                    if (orientation < 0)
                      break;
                    image->orientation=(OrientationType) orientation;
                    break;
                  }
                (void) SetImageProperty(image,keyword,options,exception);
                break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -572,6 +572,9 @@
                 if (LocaleCompare(keyword,"number-meta-channels") == 0)
                   {
                     image->number_meta_channels=StringToUnsignedLong(options);
+                    if (image->number_meta_channels > MaxPixelChannels)
+                      ThrowReaderException(CorruptImageError,
+                        "ImproperImageHeader");
                     break;
                   }
                 break;
```
