# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2019_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2019_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 43-83 of the vulnerable file.

#else
		/* Seconds to days */
		dDate = (dt / (double) SECS_PER_DAY);
#endif
	}

	return dDate;
}

date
PGTYPESdate_from_asc(char *str, char **endptr)
{
	date		dDate;
	fsec_t		fsec;
	struct tm	tt,
			   *tm = &tt;
	int			dtype;
	int			nf;
	char	   *field[MAXDATEFIELDS];
	int			ftype[MAXDATEFIELDS];
	char		lowstr[MAXDATELEN + 1];
	char	   *realptr;
	char	  **ptr = (endptr != NULL) ? endptr : &realptr;

	bool		EuroDates = FALSE;

	errno = 0;
	if (strlen(str) >= sizeof(lowstr))
	{
		errno = PGTYPES_DATE_BAD_DATE;
		return INT_MIN;
	}

	if (ParseDateTime(str, lowstr, field, ftype, &nf, ptr) != 0 ||
		DecodeDateTime(field, ftype, nf, &dtype, tm, &fsec, EuroDates) != 0)
	{
		errno = PGTYPES_DATE_BAD_DATE;
		return INT_MIN;
	}

	switch (dtype)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,14 +60,14 @@
 	int			nf;
 	char	   *field[MAXDATEFIELDS];
 	int			ftype[MAXDATEFIELDS];
-	char		lowstr[MAXDATELEN + 1];
+	char		lowstr[MAXDATELEN + MAXDATEFIELDS];
 	char	   *realptr;
 	char	  **ptr = (endptr != NULL) ? endptr : &realptr;
 
 	bool		EuroDates = FALSE;
 
 	errno = 0;
-	if (strlen(str) >= sizeof(lowstr))
+	if (strlen(str) > MAXDATELEN)
 	{
 		errno = PGTYPES_DATE_BAD_DATE;
 		return INT_MIN;
```
