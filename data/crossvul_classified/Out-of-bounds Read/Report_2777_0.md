# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2777_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2777_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1023-1063 of the vulnerable file.

	/*
	 * Update checksum of a compressed data and a extracted data.
	 */
	checksum_update(a, b, *used, *buff, *size);

	return (ARCHIVE_OK);
}

/*
 * Note that this implementation does not (and should not!) obey
 * locale settings; you cannot simply substitute strtol here, since
 * it does obey locale.
 */

static uint64_t
atol10(const char *p, size_t char_cnt)
{
	uint64_t l;
	int digit;

	l = 0;
	digit = *p - '0';
	while (digit >= 0 && digit < 10  && char_cnt-- > 0) {
		l = (l * 10) + digit;
		digit = *++p - '0';
	}
	return (l);
}

static int64_t
atol8(const char *p, size_t char_cnt)
{
	int64_t l;
	int digit;
        
	l = 0;
	while (char_cnt-- > 0) {
		if (*p >= '0' && *p <= '7')
			digit = *p - '0';
		else
			break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1040,6 +1040,9 @@
 	uint64_t l;
 	int digit;
 
+	if (char_cnt == 0)
+		return (0);
+
 	l = 0;
 	digit = *p - '0';
 	while (digit >= 0 && digit < 10  && char_cnt-- > 0) {
@@ -1054,7 +1057,10 @@
 {
 	int64_t l;
 	int digit;
-        
+
+	if (char_cnt == 0)
+		return (0);
+
 	l = 0;
 	while (char_cnt-- > 0) {
 		if (*p >= '0' && *p <= '7')
```
