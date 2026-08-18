# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5362_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5362_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2414-2454 of the vulnerable file.

	empty_streams = 0;
	for (;;) {
		int type;
		uint64_t size;
		size_t ll;

		if ((p = header_bytes(a, 1)) == NULL)
			return (-1);
		type = *p;
		if (type == kEnd)
			break;

		if (parse_7zip_uint64(a, &size) < 0)
			return (-1);
		if (zip->header_bytes_remaining < size)
			return (-1);
		ll = (size_t)size;

		switch (type) {
		case kEmptyStream:
			h->emptyStreamBools = calloc((size_t)zip->numFiles,
			    sizeof(*h->emptyStreamBools));
			if (h->emptyStreamBools == NULL)
				return (-1);
			if (read_Bools(
			    a, h->emptyStreamBools, (size_t)zip->numFiles) < 0)
				return (-1);
			empty_streams = 0;
			for (i = 0; i < zip->numFiles; i++) {
				if (h->emptyStreamBools[i])
					empty_streams++;
			}
			break;
		case kEmptyFile:
			if (empty_streams <= 0) {
				/* Unexcepted sequence. Skip this. */
				if (header_bytes(a, ll) == NULL)
					return (-1);
				break;
			}
			h->emptyFileBools = calloc(empty_streams,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2431,6 +2431,8 @@
 
 		switch (type) {
 		case kEmptyStream:
+			if (h->emptyStreamBools != NULL)
+				return (-1);
 			h->emptyStreamBools = calloc((size_t)zip->numFiles,
 			    sizeof(*h->emptyStreamBools));
 			if (h->emptyStreamBools == NULL)
@@ -2451,6 +2453,8 @@
 					return (-1);
 				break;
 			}
+			if (h->emptyFileBools != NULL)
+				return (-1);
 			h->emptyFileBools = calloc(empty_streams,
 			    sizeof(*h->emptyFileBools));
 			if (h->emptyFileBools == NULL)
@@ -2465,6 +2469,8 @@
 					return (-1);
 				break;
 			}
+			if (h->antiBools != NULL)
+				return (-1);
 			h->antiBools = calloc(empty_streams,
 			    sizeof(*h->antiBools));
 			if (h->antiBools == NULL)
@@ -2491,6 +2497,8 @@
 			if ((ll & 1) || ll < zip->numFiles * 4)
 				return (-1);
 
+			if (zip->entry_names != NULL)
+				return (-1);
 			zip->entry_names = malloc(ll);
 			if (zip->entry_names == NULL)
 				return (-1);
@@ -2543,6 +2551,8 @@
 			if ((p = header_bytes(a, 2)) == NULL)
 				return (-1);
 			allAreDefined = *p;
+			if (h->attrBools != NULL)
+				return (-1);
 			h->attrBools = calloc((size_t)zip->numFiles,
 			    sizeof(*h->attrBools));
 			if (h->attrBools == NULL)
```
