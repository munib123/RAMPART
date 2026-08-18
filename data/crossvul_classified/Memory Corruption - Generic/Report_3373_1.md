# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3373_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3373_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 2833-2860 of the vulnerable file.

      {0xffffffff, -1, 0}, {0xffffffff, -1, 0}, {0xffffffff, -1, 0}, {0xffffffff, -1, 0}, {0xffffffff, -1, 0},
      {0xffffffff, -1, 0}, {0xffffffff, -1, 0}, {0xffffffff, -1, 0}, {0xffffffff, -1, 0}, {0xffffffff, -1, 0},
      {0xffffffff, -1, 0},

      {0xfb05, 29, 2},
      {0xffffffff, -1, 0}, {0xffffffff, -1, 0}, {0xffffffff, -1, 0}, {0xffffffff, -1, 0}, {0xffffffff, -1, 0},

      {0xfb03, 0, 3},

      {0xfb01, 8, 2}
    };

  if (0 == 0)
    {
      int key = hash(&code);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          OnigCodePoint gcode = wordlist[key].code;

          if (code == gcode)
            return &wordlist[key];
        }
    }
  return 0;
}


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2850,7 +2850,7 @@
         {
           OnigCodePoint gcode = wordlist[key].code;
 
-          if (code == gcode)
+          if (code == gcode && wordlist[key].index >= 0)
             return &wordlist[key];
         }
     }
```
