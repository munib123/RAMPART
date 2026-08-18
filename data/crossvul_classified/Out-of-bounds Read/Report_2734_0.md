# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2734_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2734_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 5794-5834 of the vulnerable file.

            chunk=(unsigned char *) RelinquishMagickMemory(chunk);
            continue;
          }
        if (memcmp(type,mng_CLIP,4) == 0)
          {
            unsigned int
              first_object,
              last_object;

            /*
              Read CLIP.
            */
            if (length > 3)
              {
                first_object=(p[0] << 8) | p[1];
                last_object=(p[2] << 8) | p[3];
                p+=4;

                for (i=(int) first_object; i <= (int) last_object; i++)
                {
                  if (mng_info->exists[i] && !mng_info->frozen[i])
                    {
                      MngBox
                        box;

                      box=mng_info->object_clip[i];
                      if ((p-chunk) < (ssize_t) (length-17))
                        mng_info->object_clip[i]=
                           mng_read_box(box,(char) p[0],&p[1]);
                    }
                }

              }
            chunk=(unsigned char *) RelinquishMagickMemory(chunk);
            continue;
          }
        if (memcmp(type,mng_SAVE,4) == 0)
          {
            for (i=1; i < MNG_MAX_OBJECTS; i++)
              if (mng_info->exists[i])
                {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5811,6 +5811,8 @@
 
                 for (i=(int) first_object; i <= (int) last_object; i++)
                 {
+                  if ((i < 0) || (i >= MNG_MAX_OBJECTS))
+                    continue;
                   if (mng_info->exists[i] && !mng_info->frozen[i])
                     {
                       MngBox
```
