# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5871_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5871_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 139-179 of the vulnerable file.

			     "Unknown cipher feedback mode %i",
			     mode);
		return NULL;
	}
	if (mode == MODE_PGP) {
		PyErr_Format(PyExc_ValueError, 
			     "MODE_PGP is not supported anymore");
		return NULL;
	}
	if (KEY_SIZE!=0 && keylen!=KEY_SIZE)
	{
		PyErr_Format(PyExc_ValueError,
			     "Key must be %i bytes long, not %i",
			     KEY_SIZE, keylen);
		return NULL;
	}
	if (KEY_SIZE==0 && keylen==0)
	{
		PyErr_SetString(PyExc_ValueError,
				"Key cannot be the null string");
		return NULL;
	}
	if (IVlen != BLOCK_SIZE && mode != MODE_ECB && mode != MODE_CTR)
	{
		PyErr_Format(PyExc_ValueError,
			     "IV must be %i bytes long", BLOCK_SIZE);
		return NULL;
	}

	/* Mode-specific checks */
	if (mode == MODE_CFB) {
		if (segment_size == 0) segment_size = 8;
		if (segment_size < 1 || segment_size > BLOCK_SIZE*8 || ((segment_size & 7) != 0)) {
			PyErr_Format(PyExc_ValueError, 
				     "segment_size must be multiple of 8 (bits) "
				     "between 1 and %i", BLOCK_SIZE*8);
			return NULL;
		}
	}
	if (mode == MODE_CTR) {
		if (counter == NULL) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,6 +156,17 @@
 	{
 		PyErr_SetString(PyExc_ValueError,
 				"Key cannot be the null string");
+		return NULL;
+	}
+	if (IVlen != 0 && mode == MODE_ECB)
+	{
+		PyErr_Format(PyExc_ValueError, "ECB mode does not use IV");
+		return NULL;
+	}
+	if (IVlen != 0 && mode == MODE_CTR)
+	{
+		PyErr_Format(PyExc_ValueError,
+			"CTR mode needs counter parameter, not IV");
 		return NULL;
 	}
 	if (IVlen != BLOCK_SIZE && mode != MODE_ECB && mode != MODE_CTR)
```
