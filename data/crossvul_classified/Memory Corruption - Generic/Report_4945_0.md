# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4945_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4945_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 940-969 of the vulnerable file.

	int mymspace;
    size_t i, *adjustedsizes=(size_t *) alloca(elems*sizeof(size_t));
    if(!adjustedsizes) return 0;
    for(i=0; i<elems; i++)
	adjustedsizes[i]=sizes[i]<sizeof(threadcacheblk) ? sizeof(threadcacheblk) : sizes[i];
	GetThreadCache(&p, &tc, &mymspace, 0);
	GETMSPACE(m, p, tc, mymspace, 0,
	      ret=mspace_independent_comalloc(m, elems, adjustedsizes, chunks));
	return ret;
}

#ifdef OVERRIDE_STRDUP
/*
 * This implementation is purely there to override the libc version, to
 * avoid a crash due to allocation and free on different 'heaps'.
 */
char *strdup(const char *s1)
{
	char *s2 = 0;
	if (s1) {
		s2 = malloc(strlen(s1) + 1);
		strcpy(s2, s1);
	}
	return s2;
}
#endif

#if defined(__cplusplus)
}
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -957,8 +957,9 @@
 {
 	char *s2 = 0;
 	if (s1) {
-		s2 = malloc(strlen(s1) + 1);
-		strcpy(s2, s1);
+		size_t len = strlen(s1) + 1;
+		s2 = malloc(len);
+		memcpy(s2, s1, len);
 	}
 	return s2;
 }
```
