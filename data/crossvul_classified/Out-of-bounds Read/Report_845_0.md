# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 845_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `845_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 7100-7140 of the vulnerable file.

        break;

      case M_APP12:
        exif_process_APP12(ImageInfo, (char *)Data, itemlen);
        break;


      case M_SOF0:
      case M_SOF1:
      case M_SOF2:
      case M_SOF3:
      case M_SOF5:
      case M_SOF6:
      case M_SOF7:
      case M_SOF9:
      case M_SOF10:
      case M_SOF11:
      case M_SOF13:
      case M_SOF14:
      case M_SOF15:
        exif_process_SOFn(Data, marker, &sof_info);
        ImageInfo->Width  = sof_info.width;
        ImageInfo->Height = sof_info.height;
        if (sof_info.num_components == 3) {
          ImageInfo->IsColor = 1;
        } else {
          ImageInfo->IsColor = 0;
        }
        break;
      default:
        /* skip any other marker silently. */
        break;
    }

    /* keep track of last marker */
    last_marker = marker;
  }
  return 1;
}

/* Reallocate a file section returns 0 on success and -1 on failure */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7117,6 +7117,10 @@
       case M_SOF13:
       case M_SOF14:
       case M_SOF15:
+        if ((itemlen - 2) < 6) {
+          return 0;
+        }
+
         exif_process_SOFn(Data, marker, &sof_info);
         ImageInfo->Width  = sof_info.width;
         ImageInfo->Height = sof_info.height;
```
