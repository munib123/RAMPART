# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2683_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2683_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1022-1065 of the vulnerable file.

		if (!ND_TTEST2(*(p + offset), 2))
			return 0;
		if (length < 2)
			return 0;
		elementlen = *(p + offset + 1);

		/* Make sure we have the entire element. */
		if (!ND_TTEST2(*(p + offset + 2), elementlen))
			return 0;
		if (length < elementlen + 2)
			return 0;

		switch (*(p + offset)) {
		case E_SSID:
			memcpy(&ssid, p + offset, 2);
			offset += 2;
			length -= 2;
			if (ssid.length != 0) {
				if (ssid.length > sizeof(ssid.ssid) - 1)
					return 0;
				if (!ND_TTEST2(*(p + offset), ssid.length))
					return 0;
				if (length < ssid.length)
					return 0;
				memcpy(&ssid.ssid, p + offset, ssid.length);
				offset += ssid.length;
				length -= ssid.length;
			}
			ssid.ssid[ssid.length] = '\0';
			/*
			 * Present and not truncated.
			 *
			 * If we haven't already seen an SSID IE,
			 * copy this one, otherwise ignore this one,
			 * so we later report the first one we saw.
			 */
			if (!pbody->ssid_present) {
				pbody->ssid = ssid;
				pbody->ssid_present = 1;
			}
			break;
		case E_CHALLENGE:
			memcpy(&challenge, p + offset, 2);
			offset += 2;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1039,10 +1039,6 @@
 			if (ssid.length != 0) {
 				if (ssid.length > sizeof(ssid.ssid) - 1)
 					return 0;
-				if (!ND_TTEST2(*(p + offset), ssid.length))
-					return 0;
-				if (length < ssid.length)
-					return 0;
 				memcpy(&ssid.ssid, p + offset, ssid.length);
 				offset += ssid.length;
 				length -= ssid.length;
@@ -1068,10 +1064,6 @@
 				if (challenge.length >
 				    sizeof(challenge.text) - 1)
 					return 0;
-				if (!ND_TTEST2(*(p + offset), challenge.length))
-					return 0;
-				if (length < challenge.length)
-					return 0;
 				memcpy(&challenge.text, p + offset,
 				    challenge.length);
 				offset += challenge.length;
@@ -1096,10 +1088,6 @@
 			length -= 2;
 			if (rates.length != 0) {
 				if (rates.length > sizeof rates.rate)
-					return 0;
-				if (!ND_TTEST2(*(p + offset), rates.length))
-					return 0;
-				if (length < rates.length)
 					return 0;
 				memcpy(&rates.rate, p + offset, rates.length);
 				offset += rates.length;
@@ -1189,7 +1177,7 @@
 			offset += 3;
 			length -= 3;
 
-			memcpy(tim.bitmap, p + offset + 3, tim.length - 3);
+			memcpy(tim.bitmap, p + offset, tim.length - 3);
 			offset += tim.length - 3;
 			length -= tim.length - 3;
 			/*
```
