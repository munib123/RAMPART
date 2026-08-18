# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2019_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2019_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1154-1194 of the vulnerable file.



/* DecodeNumberField()
 * Interpret numeric string as a concatenated date or time field.
 * Use the context of previously decoded fields to help with
 * the interpretation.
 */
static int
DecodeNumberField(int len, char *str, int fmask,
				  int *tmask, struct tm * tm, fsec_t *fsec, int *is2digits)
{
	char	   *cp;

	/*
	 * Have a decimal point? Then this is a date or something with a seconds
	 * field...
	 */
	if ((cp = strchr(str, '.')) != NULL)
	{
#ifdef HAVE_INT64_TIMESTAMP
		char		fstr[MAXDATELEN + 1];

		/*
		 * OK, we have at most six digits to care about. Let's construct a
		 * string and then do the conversion to an integer.
		 */
		strcpy(fstr, (cp + 1));
		strcpy(fstr + strlen(fstr), "000000");
		*(fstr + 6) = '\0';
		*fsec = strtol(fstr, NULL, 10);
#else
		*fsec = strtod(cp, NULL);
#endif
		*cp = '\0';
		len = strlen(str);
	}
	/* No decimal point and no complete date yet? */
	else if ((fmask & DTK_DATE_M) != DTK_DATE_M)
	{
		/* yyyymmdd? */
		if (len == 8)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1171,15 +1171,22 @@
 	if ((cp = strchr(str, '.')) != NULL)
 	{
 #ifdef HAVE_INT64_TIMESTAMP
-		char		fstr[MAXDATELEN + 1];
+		char		fstr[7];
+		int			i;
+
+		cp++;
 
 		/*
 		 * OK, we have at most six digits to care about. Let's construct a
-		 * string and then do the conversion to an integer.
+		 * string with those digits, zero-padded on the right, and then do
+		 * the conversion to an integer.
+		 *
+		 * XXX This truncates the seventh digit, unlike rounding it as do
+		 * the backend and the !HAVE_INT64_TIMESTAMP case.
 		 */
-		strcpy(fstr, (cp + 1));
-		strcpy(fstr + strlen(fstr), "000000");
-		*(fstr + 6) = '\0';
+		for (i = 0; i < 6; i++)
+			fstr[i] = *cp != '\0' ? *cp++ : '0';
+		fstr[i] = '\0';
 		*fsec = strtol(fstr, NULL, 10);
 #else
 		*fsec = strtod(cp, NULL);
@@ -1531,15 +1538,22 @@
 		else if (*cp == '.')
 		{
 #ifdef HAVE_INT64_TIMESTAMP
-			char		fstr[MAXDATELEN + 1];
+			char		fstr[7];
+			int			i;
+
+			cp++;
 
 			/*
-			 * OK, we have at most six digits to work with. Let's construct a
-			 * string and then do the conversion to an integer.
+			 * OK, we have at most six digits to care about. Let's construct a
+			 * string with those digits, zero-padded on the right, and then do
+			 * the conversion to an integer.
+			 *
+			 * XXX This truncates the seventh digit, unlike rounding it as do
+			 * the backend and the !HAVE_INT64_TIMESTAMP case.
 			 */
-			strncpy(fstr, (cp + 1), 7);
-			strcpy(fstr + strlen(fstr), "000000");
-			*(fstr + 6) = '\0';
+			for (i = 0; i < 6; i++)
+				fstr[i] = *cp != '\0' ? *cp++ : '0';
+			fstr[i] = '\0';
 			*fsec = strtol(fstr, &cp, 10);
 #else
 			str = cp;
@@ -1665,6 +1679,9 @@
  *	DTK_NUMBER can hold date fields (yy.ddd)
  *	DTK_STRING can hold months (January) and time zones (PST)
  *	DTK_DATE can hold Posix time zones (GMT-8)
+ *
+ * The "lowstr" work buffer must have at least strlen(timestr) + MAXDATEFIELDS
+ * bytes of space.  On output, field[] entries will point into it.
  */
 int
 ParseDateTime(char *timestr, char *lowstr,
@@ -1677,7 +1694,10 @@
 	/* outer loop through fields */
 	while (*(*endstr) != '\0')
 	{
+		/* Record start of current field */
 		field[nf] = lp;
+		if (nf >= MAXDATEFIELDS)
+			return -1;
 
 		/* leading digit? then date or time */
 		if (isdigit((unsigned char) *(*endstr)))
@@ -1818,8 +1838,6 @@
 		/* force in a delimiter after each field */
 		*lp++ = '\0';
 		nf++;
-		if (nf > MAXDATEFIELDS)
-			return -1;
 	}
 
 	*numfields = nf;
```
