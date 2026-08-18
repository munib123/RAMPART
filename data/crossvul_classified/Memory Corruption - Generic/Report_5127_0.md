# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5127_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5127_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 3536-3576 of the vulnerable file.

              if (image->debug != MagickFalse)
                {
                  (void) FormatMagickSize(cache_info->length,MagickFalse,"B",
                    MagickPathExtent,format);
                  type=CommandOptionToMnemonic(MagickCacheOptions,(ssize_t)
                    cache_info->type);
                  (void) FormatLocaleString(message,MagickPathExtent,
                    "open %s (%s[%d], %s, %.20gx%.20gx%.20g %s)",
                    cache_info->filename,cache_info->cache_filename,
                    GetDistributeCacheFile((DistributeCacheInfo *)
                    cache_info->server_info),type,(double) cache_info->columns,
                    (double) cache_info->rows,(double)
                    cache_info->number_channels,format);
                  (void) LogMagickEvent(CacheEvent,GetMagickModule(),"%s",
                    message);
                }
              return(MagickTrue);
            }
        }
      RelinquishMagickResource(DiskResource,cache_info->length);
      (void) ThrowMagickException(exception,GetMagickModule(),CacheError,
        "CacheResourcesExhausted","`%s'",image->filename);
      return(MagickFalse);
    }
  if ((source_info.storage_class != UndefinedClass) && (mode != ReadMode))
    {
      (void) ClosePixelCacheOnDisk(cache_info);
      *cache_info->cache_filename='\0';
    }
  if (OpenPixelCacheOnDisk(cache_info,mode) == MagickFalse)
    {
      RelinquishMagickResource(DiskResource,cache_info->length);
      ThrowFileException(exception,CacheError,"UnableToOpenPixelCache",
        image->filename);
      return(MagickFalse);
    }
  status=SetPixelCacheExtent(image,(MagickSizeType) cache_info->offset+
    cache_info->length);
  if (status == MagickFalse)
    {
      ThrowFileException(exception,CacheError,"UnableToExtendCache",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3553,6 +3553,7 @@
             }
         }
       RelinquishMagickResource(DiskResource,cache_info->length);
+      cache_info->type=UndefinedCache;
       (void) ThrowMagickException(exception,GetMagickModule(),CacheError,
         "CacheResourcesExhausted","`%s'",image->filename);
       return(MagickFalse);
@@ -3565,6 +3566,7 @@
   if (OpenPixelCacheOnDisk(cache_info,mode) == MagickFalse)
     {
       RelinquishMagickResource(DiskResource,cache_info->length);
+      cache_info->type=UndefinedCache;
       ThrowFileException(exception,CacheError,"UnableToOpenPixelCache",
         image->filename);
       return(MagickFalse);
@@ -3573,6 +3575,7 @@
     cache_info->length);
   if (status == MagickFalse)
     {
+      cache_info->type=UndefinedCache;
       ThrowFileException(exception,CacheError,"UnableToExtendCache",
         image->filename);
       return(MagickFalse);
@@ -3631,6 +3634,8 @@
                   (void) LogMagickEvent(CacheEvent,GetMagickModule(),"%s",
                     message);
                 }
+              if (status == MagickFalse)
+                cache_info->type=UndefinedCache;
               return(status);
             }
         }
@@ -3655,6 +3660,8 @@
         cache_info->number_channels,format);
       (void) LogMagickEvent(CacheEvent,GetMagickModule(),"%s",message);
     }
+  if (status == MagickFalse)
+    cache_info->type=UndefinedCache;
   return(status);
 }
 
```
