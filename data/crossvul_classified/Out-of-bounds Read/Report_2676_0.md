# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2676_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2676_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 790-830 of the vulnerable file.

	const char *sfsname = NULL;
	char *spacep;

	if (ndo->ndo_uflag) {
		u_int i;
		char const *sep = "";

		ND_PRINT((ndo, " fh["));
		for (i=0; i<len; i++) {
			ND_PRINT((ndo, "%s%x", sep, dp[i]));
			sep = ":";
		}
		ND_PRINT((ndo, "]"));
		return;
	}

	Parse_fh((const u_char *)dp, len, &fsid, &ino, NULL, &sfsname, 0);

	if (sfsname) {
		/* file system ID is ASCII, not numeric, for this server OS */
		static char temp[NFSX_V3FHMAX+1];

		/* Make sure string is null-terminated */
		strncpy(temp, sfsname, NFSX_V3FHMAX);
		temp[sizeof(temp) - 1] = '\0';
		/* Remove trailing spaces */
		spacep = strchr(temp, ' ');
		if (spacep)
			*spacep = '\0';

		ND_PRINT((ndo, " fh %s/", temp));
	} else {
		ND_PRINT((ndo, " fh %d,%d/",
			     fsid.Fsid_dev.Major, fsid.Fsid_dev.Minor));
	}

	if(fsid.Fsid_dev.Minor == 257)
		/* Print the undecoded handle */
		ND_PRINT((ndo, "%s", fsid.Opaque_Handle));
	else
		ND_PRINT((ndo, "%ld", (long) ino));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -807,11 +807,15 @@
 
 	if (sfsname) {
 		/* file system ID is ASCII, not numeric, for this server OS */
-		static char temp[NFSX_V3FHMAX+1];
+		char temp[NFSX_V3FHMAX+1];
+		u_int stringlen;
 
 		/* Make sure string is null-terminated */
-		strncpy(temp, sfsname, NFSX_V3FHMAX);
-		temp[sizeof(temp) - 1] = '\0';
+		stringlen = len;
+		if (stringlen > NFSX_V3FHMAX)
+			stringlen = NFSX_V3FHMAX;
+		strncpy(temp, sfsname, stringlen);
+		temp[stringlen] = '\0';
 		/* Remove trailing spaces */
 		spacep = strchr(temp, ' ');
 		if (spacep)
```
