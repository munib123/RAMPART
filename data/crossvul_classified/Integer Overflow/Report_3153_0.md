# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3153_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3153_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1578-1618 of the vulnerable file.

 * Returns zero when OK, SP_ value for an error.
 */
    static int
spell_read_tree(
    FILE	*fd,
    char_u	**bytsp,
    idx_T	**idxsp,
    int		prefixtree,	/* TRUE for the prefix tree */
    int		prefixcnt)	/* when "prefixtree" is TRUE: prefix count */
{
    int		len;
    int		idx;
    char_u	*bp;
    idx_T	*ip;

    /* The tree size was computed when writing the file, so that we can
     * allocate it as one long block. <nodecount> */
    len = get4c(fd);
    if (len < 0)
	return SP_TRUNCERROR;
    if (len > 0)
    {
	/* Allocate the byte array. */
	bp = lalloc((long_u)len, TRUE);
	if (bp == NULL)
	    return SP_OTHERERROR;
	*bytsp = bp;

	/* Allocate the index array. */
	ip = (idx_T *)lalloc_clear((long_u)(len * sizeof(int)), TRUE);
	if (ip == NULL)
	    return SP_OTHERERROR;
	*idxsp = ip;

	/* Recursively read the tree and store it in the array. */
	idx = read_tree_node(fd, bp, ip, len, 0, prefixtree, prefixcnt);
	if (idx < 0)
	    return idx;
    }
    return 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1595,6 +1595,9 @@
     len = get4c(fd);
     if (len < 0)
 	return SP_TRUNCERROR;
+    if (len >= 0x3ffffff)
+	/* Invalid length, multiply with sizeof(int) would overflow. */
+	return SP_FORMERROR;
     if (len > 0)
     {
 	/* Allocate the byte array. */
```
