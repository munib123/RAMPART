# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_8
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_8`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1349-1389 of the vulnerable file.

	{
		j = (i + 1) % path->npts;
		area += path->p[i].x * path->p[j].y;
		area -= path->p[i].y * path->p[j].x;
	}

	area *= 0.5;
	PG_RETURN_FLOAT8(area < 0.0 ? -area : area);
}


Datum
path_in(PG_FUNCTION_ARGS)
{
	char	   *str = PG_GETARG_CSTRING(0);
	PATH	   *path;
	int			isopen;
	char	   *s;
	int			npts;
	int			size;
	int			depth = 0;

	if ((npts = pair_count(str, ',')) <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("invalid input syntax for type path: \"%s\"", str)));

	s = str;
	while (isspace((unsigned char) *s))
		s++;

	/* skip single leading paren */
	if ((*s == LDELIM) && (strrchr(s, LDELIM) == s))
	{
		s++;
		depth++;
	}

	size = offsetof(PATH, p[0]) +sizeof(path->p[0]) * npts;
	path = (PATH *) palloc(size);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1366,6 +1366,7 @@
 	char	   *s;
 	int			npts;
 	int			size;
+	int			base_size;
 	int			depth = 0;
 
 	if ((npts = pair_count(str, ',')) <= 0)
@@ -1384,7 +1385,15 @@
 		depth++;
 	}
 
-	size = offsetof(PATH, p[0]) +sizeof(path->p[0]) * npts;
+	base_size = sizeof(path->p[0]) * npts;
+	size = offsetof(PATH, p[0]) + base_size;
+
+	/* Check for integer overflow */
+	if (base_size / npts != sizeof(path->p[0]) || size <= base_size)
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+				 errmsg("too many points requested")));
+
 	path = (PATH *) palloc(size);
 
 	SET_VARSIZE(path, size);
@@ -3429,6 +3438,7 @@
 	POLYGON    *poly;
 	int			npts;
 	int			size;
+	int			base_size;
 	int			isopen;
 	char	   *s;
 
@@ -3437,7 +3447,15 @@
 				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
 			  errmsg("invalid input syntax for type polygon: \"%s\"", str)));
 
-	size = offsetof(POLYGON, p[0]) +sizeof(poly->p[0]) * npts;
+	base_size = sizeof(poly->p[0]) * npts;
+	size = offsetof(POLYGON, p[0]) + base_size;
+
+	/* Check for integer overflow */
+	if (base_size / npts != sizeof(poly->p[0]) || size <= base_size)
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+				 errmsg("too many points requested")));
+
 	poly = (POLYGON *) palloc0(size);	/* zero any holes */
 
 	SET_VARSIZE(poly, size);
@@ -4343,6 +4361,10 @@
 				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
 				 errmsg("open path cannot be converted to polygon")));
 
+	/*
+	 * Never overflows: the old size fit in MaxAllocSize, and the new size is
+	 * just a small constant larger.
+	 */
 	size = offsetof(POLYGON, p[0]) +sizeof(poly->p[0]) * path->npts;
 	poly = (POLYGON *) palloc(size);
 
@@ -4448,6 +4470,10 @@
 	int			size;
 	int			i;
 
+	/*
+	 * Never overflows: the old size fit in MaxAllocSize, and the new size is
+	 * smaller by a small constant.
+	 */
 	size = offsetof(PATH, p[0]) +sizeof(path->p[0]) * poly->npts;
 	path = (PATH *) palloc(size);
 
```
