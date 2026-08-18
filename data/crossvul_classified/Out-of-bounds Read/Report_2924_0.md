# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2924_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2924_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 213-256 of the vulnerable file.


	/* For parsing logic */
	int   inputnum = 0;
	__u32 usage = 0;

	/* Global Values, indexed by TAG */
	__u32 globalval[TAG_GLOB_MAX];
	__u32 oldval[TAG_GLOB_MAX];

	/* Debug stuff */
	char  maintype = 'x';
	char  globtype[12];
	int   indent = 0;
	char  indentstr[10] = "";


	dev_dbg(ddev, "======>>>>>>PARSE<<<<<<======\n");

	/* Walk  this report and pull out the info we need */
	while (i < length) {
		prefix = report[i];

		/* Skip over prefix */
		i++;

		/* Determine data size and save the data in the proper variable */
		size = PREF_SIZE(prefix);
		switch (size) {
		case 1:
			data = report[i];
			break;
		case 2:
			data16 = get_unaligned_le16(&report[i]);
			break;
		case 3:
			size = 4;
			data32 = get_unaligned_le32(&report[i]);
			break;
		}

		/* Skip size of data */
		i += size;

		/* What we do depends on the tag type */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -230,13 +230,17 @@
 
 	/* Walk  this report and pull out the info we need */
 	while (i < length) {
-		prefix = report[i];
-
-		/* Skip over prefix */
-		i++;
+		prefix = report[i++];
 
 		/* Determine data size and save the data in the proper variable */
-		size = PREF_SIZE(prefix);
+		size = (1U << PREF_SIZE(prefix)) >> 1;
+		if (i + size > length) {
+			dev_err(ddev,
+				"Not enough data (need %d, have %d)\n",
+				i + size, length);
+			break;
+		}
+
 		switch (size) {
 		case 1:
 			data = report[i];
@@ -244,8 +248,7 @@
 		case 2:
 			data16 = get_unaligned_le16(&report[i]);
 			break;
-		case 3:
-			size = 4;
+		case 4:
 			data32 = get_unaligned_le32(&report[i]);
 			break;
 		}
```
