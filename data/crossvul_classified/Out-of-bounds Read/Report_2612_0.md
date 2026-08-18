# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2612_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2612_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 5861-5901 of the vulnerable file.


            continue;
          }

        if (memcmp(type,mng_MOVE,4) == 0)
          {
            size_t
              first_object,
              last_object;

            /* read MOVE */

            if (length > 3)
            {
              first_object=(p[0] << 8) | p[1];
              last_object=(p[2] << 8) | p[3];
              p+=4;

              for (i=(ssize_t) first_object; i <= (ssize_t) last_object; i++)
              {
                if (mng_info->exists[i] && !mng_info->frozen[i] &&
                    (p-chunk) < (ssize_t) (length-8))
                  {
                    MngPair
                      new_pair;

                    MngPair
                      old_pair;

                    old_pair.a=mng_info->x_off[i];
                    old_pair.b=mng_info->y_off[i];
                    new_pair=mng_read_pair(old_pair,(int) p[0],&p[1]);
                    mng_info->x_off[i]=new_pair.a;
                    mng_info->y_off[i]=new_pair.b;
                  }
              }
            }

            chunk=(unsigned char *) RelinquishMagickMemory(chunk);
            continue;
          }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5878,6 +5878,8 @@
 
               for (i=(ssize_t) first_object; i <= (ssize_t) last_object; i++)
               {
+                if ((i < 0) || (i >= MNG_MAX_OBJECTS))
+                  continue;
                 if (mng_info->exists[i] && !mng_info->frozen[i] &&
                     (p-chunk) < (ssize_t) (length-8))
                   {
```
