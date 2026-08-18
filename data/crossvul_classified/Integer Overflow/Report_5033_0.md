# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5033_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5033_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 2136-2176 of the vulnerable file.

	int type;
	unsigned i;
	uint32_t numDigests;

	memset(ss, 0, sizeof(*ss));

	for (i = 0; i < numFolders; i++)
		f[i].numUnpackStreams = 1;

	if ((p = header_bytes(a, 1)) == NULL)
		return (-1);
	type = *p;

	if (type == kNumUnPackStream) {
		unpack_streams = 0;
		for (i = 0; i < numFolders; i++) {
			if (parse_7zip_uint64(a, &(f[i].numUnpackStreams)) < 0)
				return (-1);
			if (UMAX_ENTRY < f[i].numUnpackStreams)
				return (-1);
			unpack_streams += (size_t)f[i].numUnpackStreams;
		}
		if ((p = header_bytes(a, 1)) == NULL)
			return (-1);
		type = *p;
	} else
		unpack_streams = numFolders;

	ss->unpack_streams = unpack_streams;
	if (unpack_streams) {
		ss->unpackSizes = calloc(unpack_streams,
		    sizeof(*ss->unpackSizes));
		ss->digestsDefined = calloc(unpack_streams,
		    sizeof(*ss->digestsDefined));
		ss->digests = calloc(unpack_streams,
		    sizeof(*ss->digests));
		if (ss->unpackSizes == NULL || ss->digestsDefined == NULL ||
		    ss->digests == NULL)
			return (-1);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2153,6 +2153,9 @@
 				return (-1);
 			if (UMAX_ENTRY < f[i].numUnpackStreams)
 				return (-1);
+			if (unpack_streams > SIZE_MAX - UMAX_ENTRY) {
+				return (-1);
+			}
 			unpack_streams += (size_t)f[i].numUnpackStreams;
 		}
 		if ((p = header_bytes(a, 1)) == NULL)
```
