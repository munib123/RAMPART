# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 4472_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4472_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 213-253 of the vulnerable file.

int
srs_timestamp_create(srs_t *srs __attribute__((unused)), char *buf, time_t now)
{
	now = now / SRS_TIME_PRECISION;
	buf[1] = SRS_TIME_BASECHARS[now & ((1 << SRS_TIME_BASEBITS) - 1)];
	now = now >> SRS_TIME_BASEBITS;
	buf[0] = SRS_TIME_BASECHARS[now & ((1 << SRS_TIME_BASEBITS) - 1)];
	buf[2] = '\0';
	return SRS_SUCCESS;
}

int
srs_timestamp_check(srs_t *srs, const char *stamp)
{
	const char	*sp;
	char		*bp;
	int			 off;
	time_t		 now;
	time_t		 then;

	/* We had better go around this loop exactly twice! */
	then = 0;
	for (sp = stamp; *sp; sp++) {
		bp = strchr(SRS_TIME_BASECHARS, toupper(*sp));
		if (bp == NULL)
			return SRS_EBADTIMESTAMPCHAR;
		off = bp - SRS_TIME_BASECHARS;
		then = (then << SRS_TIME_BASEBITS) | off;
	}

	time(&now);
	now = (now / SRS_TIME_PRECISION) % SRS_TIME_SLOTS;
	while (now < then)
		now = now + SRS_TIME_SLOTS;

	if (now <= then + srs->maxage)
		return SRS_SUCCESS;
	return SRS_ETIMESTAMPOUTOFDATE;
}

const char *SRS_HASH_BASECHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -230,6 +230,7 @@
 	time_t		 now;
 	time_t		 then;
 
+	if (strlen(stamp) != 2) return SRS_ETIMESTAMPOUTOFDATE;
 	/* We had better go around this loop exactly twice! */
 	then = 0;
 	for (sp = stamp; *sp; sp++) {
```
