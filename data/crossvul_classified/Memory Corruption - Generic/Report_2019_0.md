# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2019_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2019_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 171-216 of the vulnerable file.


#define DTK_DOW			32
#define DTK_DOY			33
#define DTK_TZ_HOUR		34
#define DTK_TZ_MINUTE	35
#define DTK_ISOYEAR		36
#define DTK_ISODOW		37


/*
 * Bit mask definitions for time parsing.
 */

#define DTK_M(t)		(0x01 << (t))

/* Convenience: a second, plus any fractional component */
#define DTK_ALL_SECS_M	(DTK_M(SECOND) | DTK_M(MILLISECOND) | DTK_M(MICROSECOND))
#define DTK_DATE_M		(DTK_M(YEAR) | DTK_M(MONTH) | DTK_M(DAY))
#define DTK_TIME_M		(DTK_M(HOUR) | DTK_M(MINUTE) | DTK_ALL_SECS_M)

#define MAXDATELEN		63		/* maximum possible length of an input date
								 * string (not counting tr. null) */
#define MAXDATEFIELDS	25		/* maximum possible number of fields in a date
								 * string */
#define TOKMAXLEN		10		/* only this many chars are stored in
								 * datetktbl */

/* keep this struct small; it gets used a lot */
typedef struct
{
	char		token[TOKMAXLEN];
	char		type;
	char		value;			/* this may be unsigned, alas */
} datetkn;

/* one of its uses is in tables of time zone abbreviations */
typedef struct TimeZoneAbbrevTable
{
	int			numabbrevs;
	datetkn		abbrevs[1];		/* VARIABLE LENGTH ARRAY */
} TimeZoneAbbrevTable;


/* FMODULO()
 * Macro to replace modf(), which is broken on some platforms.
 * t = input and remainder
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,12 +188,17 @@
 #define DTK_DATE_M		(DTK_M(YEAR) | DTK_M(MONTH) | DTK_M(DAY))
 #define DTK_TIME_M		(DTK_M(HOUR) | DTK_M(MINUTE) | DTK_ALL_SECS_M)
 
-#define MAXDATELEN		63		/* maximum possible length of an input date
-								 * string (not counting tr. null) */
-#define MAXDATEFIELDS	25		/* maximum possible number of fields in a date
-								 * string */
-#define TOKMAXLEN		10		/* only this many chars are stored in
-								 * datetktbl */
+/*
+ * Working buffer size for input and output of interval, timestamp, etc.
+ * Inputs that need more working space will be rejected early.  Longer outputs
+ * will overrun buffers, so this must suffice for all possible output.  As of
+ * this writing, interval_out() needs the most space at ~90 bytes.
+ */
+#define MAXDATELEN		128
+/* maximum possible number of fields in a date string */
+#define MAXDATEFIELDS	25
+/* only this many chars are stored in datetktbl */
+#define TOKMAXLEN		10
 
 /* keep this struct small; it gets used a lot */
 typedef struct
```
