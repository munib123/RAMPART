# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 486_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `486_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 777-817 of the vulnerable file.

	indexh = 0;
	while (indexh < height)
	{
		out = (org_out + width * height * 4) - ((indexh + 1) * width * 4);
		color = 0;
		this_line = out;
		indexw = 0;
		if (last_line == 0)
		{
			while (indexw < width)
			{
				code = CVAL(in);
				replen = code & 0xf;
				collen = (code >> 4) & 0xf;
				revcode = (replen << 4) | collen;
				if ((revcode <= 47) && (revcode >= 16))
				{
					replen = revcode;
					collen = 0;
				}
				while (collen > 0)
				{
					color = CVAL(in);
					*out = color;
					out += 4;
					indexw++;
					collen--;
				}
				while (replen > 0)
				{
					*out = color;
					out += 4;
					indexw++;
					replen--;
				}
			}
		}
		else
		{
			while (indexw < width)
			{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -794,7 +794,7 @@
 					replen = revcode;
 					collen = 0;
 				}
-				while (collen > 0)
+				while (indexw < width && collen > 0)
 				{
 					color = CVAL(in);
 					*out = color;
@@ -802,7 +802,7 @@
 					indexw++;
 					collen--;
 				}
-				while (replen > 0)
+				while (indexw < width && replen > 0)
 				{
 					*out = color;
 					out += 4;
@@ -824,7 +824,7 @@
 					replen = revcode;
 					collen = 0;
 				}
-				while (collen > 0)
+				while (indexw < width && collen > 0)
 				{
 					x = CVAL(in);
 					if (x & 1)
@@ -844,7 +844,7 @@
 					indexw++;
 					collen--;
 				}
-				while (replen > 0)
+				while (indexw < width && replen > 0)
 				{
 					x = last_line[indexw * 4] + color;
 					*out = x;
```
