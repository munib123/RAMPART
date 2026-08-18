# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 2303_3
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2303_3`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 312-352 of the vulnerable file.


		WideCharToMultiByte(CP_ACP, 0, name, -1, mbname, mbsize,
				    NULL, NULL);
	}

	tif = TIFFFdOpen((int)fd,
			 (mbname != NULL) ? mbname : "<unknown>", mode);
	if(!tif)
		CloseHandle(fd);

	_TIFFfree(mbname);

	return tif;
}

#endif /* ndef _WIN32_WCE */

void*
_TIFFmalloc(tmsize_t s)
{
	return (malloc((size_t) s));
}

void
_TIFFfree(void* p)
{
	free(p);
}

void*
_TIFFrealloc(void* p, tmsize_t s)
{
	return (realloc(p, (size_t) s));
}

void
_TIFFmemset(void* p, int v, tmsize_t c)
{
	memset(p, v, (size_t) c);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -329,6 +329,9 @@
 void*
 _TIFFmalloc(tmsize_t s)
 {
+        if (s == 0)
+                return ((void *) NULL);
+
 	return (malloc((size_t) s));
 }
 
```
