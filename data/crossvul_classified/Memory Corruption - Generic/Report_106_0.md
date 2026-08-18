# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 106_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `106_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 2043-2083 of the vulnerable file.

		if (match32->match_size > size_left)
			return -EINVAL;

		size_left -= match32->match_size;

		ret = compat_mtw_from_user(match32, type, state, base);
		if (ret < 0)
			return ret;

		if (WARN_ON(ret < match32->match_size))
			return -EINVAL;
		growth += ret - match32->match_size;
		growth += ebt_compat_entry_padsize();

		buf += sizeof(*match32);
		buf += match32->match_size;

		if (match_kern)
			match_kern->match_size = ret;

		WARN_ON(type == EBT_COMPAT_TARGET && size_left);
		match32 = (struct compat_ebt_entry_mwt *) buf;
	}

	return growth;
}

/* called for all ebt_entry structures. */
static int size_entry_mwt(struct ebt_entry *entry, const unsigned char *base,
			  unsigned int *total,
			  struct ebt_entries_buf_state *state)
{
	unsigned int i, j, startoff, new_offset = 0;
	/* stores match/watchers/targets & offset of next struct ebt_entry: */
	unsigned int offsets[4];
	unsigned int *offsets_update = NULL;
	int ret;
	char *buf_start;

	if (*total < sizeof(struct ebt_entries))
		return -EINVAL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2060,7 +2060,9 @@
 		if (match_kern)
 			match_kern->match_size = ret;
 
-		WARN_ON(type == EBT_COMPAT_TARGET && size_left);
+		if (WARN_ON(type == EBT_COMPAT_TARGET && size_left))
+			return -EINVAL;
+
 		match32 = (struct compat_ebt_entry_mwt *) buf;
 	}
 
@@ -2116,6 +2118,15 @@
 	 *
 	 * offsets are relative to beginning of struct ebt_entry (i.e., 0).
 	 */
+	for (i = 0; i < 4 ; ++i) {
+		if (offsets[i] >= *total)
+			return -EINVAL;
+		if (i == 0)
+			continue;
+		if (offsets[i-1] > offsets[i])
+			return -EINVAL;
+	}
+
 	for (i = 0, j = 1 ; j < 4 ; j++, i++) {
 		struct compat_ebt_entry_mwt *match32;
 		unsigned int size;
```
