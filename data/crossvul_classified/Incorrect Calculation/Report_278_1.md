# CrossVul Fix Pair: Incorrect Calculation in c
**Pair ID:** 278_1
**Vulnerability Class:** Incorrect Calculation
**CWE:** CWE-682
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `278_1`)

## Vulnerability Information & PoC

## Description
Incorrect Calculation - When product performs a security-critical calculation incorrectly, it might lead to incorrect resource allocations, incorrect privilege assignments, or failed comparisons among other things.

## Vulnerable Code
```c
Lines 814-854 of the vulnerable file.


     /* PMGL? not found. PMGI? maybe found */
     return (is_pmgl) ? 0 : (*result ? 1 : 0);

 chunk_end:
    D(("reached end of chunk data while searching"))
    return -1;
}

#if HAVE_TOWLOWER
# if HAVE_WCTYPE_H
#  include <wctype.h>
# endif
# define TOLOWER(x) towlower(x)
#elif HAVE_TOLOWER
# if HAVE_CTYPE_H
#  include <ctype.h>
# endif
# define TOLOWER(x) tolower(x)
#else
# define TOLOWER(x) (((x)<0||(x)>256)?(x):mspack_tolower_map[(x)])
/* Map of char -> lowercase char for the first 256 chars. Generated with:
 * LC_CTYPE=en_GB.utf-8 perl -Mlocale -le 'print map{ord(lc chr).","} 0..255'
 */
static const unsigned char mspack_tolower_map[256] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,
    28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,
    53,54,55,56,57,58,59,60,61,62,63,64,97,98,99,100,101,102,103,104,105,106,
    107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,91,92,93,94,
    95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,
    115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,
    134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,
    153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,
    172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,
    191,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,
    242,243,244,245,246,215,248,249,250,251,252,253,254,223,224,225,226,227,228,
    229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,
    248,249,250,251,252,253,254,255
};
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -831,7 +831,7 @@
 # endif
 # define TOLOWER(x) tolower(x)
 #else
-# define TOLOWER(x) (((x)<0||(x)>256)?(x):mspack_tolower_map[(x)])
+# define TOLOWER(x) (((x)<0||(x)>255)?(x):mspack_tolower_map[(x)])
 /* Map of char -> lowercase char for the first 256 chars. Generated with:
  * LC_CTYPE=en_GB.utf-8 perl -Mlocale -le 'print map{ord(lc chr).","} 0..255'
  */
```
