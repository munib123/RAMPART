# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2567_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2567_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 1894-1934 of the vulnerable file.

      p=GetStringInfoDatum(profile);

      if (*p != 'E')
        {
          /* Initialize profile with "Exif\0\0" if it is not
             already present by accident
          */
          *p++ ='E';
          *p++ ='x';
          *p++ ='i';
          *p++ ='f';
          *p++ ='\0';
          *p++ ='\0';
        }
      else
        {
          if (p[1] != 'x' || p[2] != 'i' || p[3] != 'f' ||
              p[4] != '\0' || p[5] != '\0')
            {
              /* Chunk is malformed */
              return(-1);
            }
         }

      /* copy chunk->data to profile */
      s=chunk->data;
      for (i=0; i<chunk->size; i++)
        *p++ = *s++;

      error_info=(PNGErrorInfo *) png_get_error_ptr(ping);
      (void) SetImageProfile(image,"exif",profile,
        error_info->exception);

      return(1);
    }

  /* vpAg (deprecated, replaced by caNv) */
  if (chunk->name[0] == 118 &&
      chunk->name[1] == 112 &&
      chunk->name[2] ==  65 &&
      chunk->name[3] == 103)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1911,6 +1911,7 @@
               p[4] != '\0' || p[5] != '\0')
             {
               /* Chunk is malformed */
+              profile=DestroyStringInfo(profile);
               return(-1);
             }
          }
@@ -1923,6 +1924,8 @@
       error_info=(PNGErrorInfo *) png_get_error_ptr(ping);
       (void) SetImageProfile(image,"exif",profile,
         error_info->exception);
+
+      profile=DestroyStringInfo(profile);
 
       return(1);
     }
@@ -2297,6 +2300,7 @@
       /*
         PNG image is corrupt.
       */
+      printf("  destroy_read_struct\n");
       png_destroy_read_struct(&ping,&ping_info,&end_info);
 
 #ifdef IMPNG_SETJMP_NOT_THREAD_SAFE
```
