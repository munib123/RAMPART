# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 2303_2
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2303_2`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 247-287 of the vulnerable file.

		 * creat does the right thing.
                 */
                fd = creat((char *) /* bug in stdio.h */ name, 0666,
		    "alq = 128", "deq = 64", "mbc = 32",
		    "fop = tef");
	} else if (m&O_RDWR) {
		fd = open(name, m, 0666,
		    "deq = 64", "mbc = 32", "fop = tef", "ctx = stm");
	} else
		fd = open(name, m, 0666, "mbc = 32", "ctx = stm");
	if (fd < 0) {
		TIFFErrorExt(0, module, "%s: Cannot open", name);
		return ((TIFF*)0);
	}
	return (TIFFFdOpen(fd, name, mode));
}

tdata_t
_TIFFmalloc(tsize_t s)
{
	return (malloc((size_t) s));
}

void
_TIFFfree(tdata_t p)
{
	free(p);
}

tdata_t
_TIFFrealloc(tdata_t p, tsize_t s)
{
	return (realloc(p, (size_t) s));
}

void
_TIFFmemset(tdata_t p, int v, tsize_t c)
{
	memset(p, v, (size_t) c);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -264,6 +264,9 @@
 tdata_t
 _TIFFmalloc(tsize_t s)
 {
+        if (s == 0)
+                return ((void *) NULL);
+
 	return (malloc((size_t) s));
 }
 
```
