# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 3976_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3976_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 138-174 of the vulnerable file.

bool Scanner::fill(size_t need)
{
    if (eof) return false;

    pop_finished_files();

    DASSERT(bot <= tok && tok <= lim);
    size_t free = static_cast<size_t>(tok - bot);
    size_t copy = static_cast<size_t>(lim - tok);

    if (free >= need) {
        memmove(bot, tok, copy);
        shift_ptrs_and_fpos(-static_cast<ptrdiff_t>(free));
    }
    else {
        BSIZE += std::max(BSIZE, need);
        char * buf = new char[BSIZE + YYMAXFILL];
        if (!buf) fatal("out of memory");

        memmove(buf, tok, copy);
        shift_ptrs_and_fpos(buf - bot);
        delete [] bot;
        bot = buf;

        free = BSIZE - copy;
    }

    if (!read(free)) {
        eof = lim;
        memset(lim, 0, YYMAXFILL);
        lim += YYMAXFILL;
    }

    return true;
}

} // namespace re2c
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,13 +155,14 @@
         if (!buf) fatal("out of memory");
 
         memmove(buf, tok, copy);
-        shift_ptrs_and_fpos(buf - bot);
+        shift_ptrs_and_fpos(buf - tok);
         delete [] bot;
         bot = buf;
 
         free = BSIZE - copy;
     }
 
+    DASSERT(lim + free <= bot + BSIZE);
     if (!read(free)) {
         eof = lim;
         memset(lim, 0, YYMAXFILL);
```
