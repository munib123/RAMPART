# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 140_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `140_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 331-371 of the vulnerable file.

	RList *secs = sections (bf);
	RListIter *iter;
	RBinSection *sec;
	int i, type;
	r_list_foreach (secs, iter, sec) {
		type = -1;
		if (!strcmp (sec->name, ".fini_array")) {
			type = R_BIN_ENTRY_TYPE_FINI;
		} else if (!strcmp (sec->name, ".init_array")) {
			type = R_BIN_ENTRY_TYPE_INIT;
		} else if (!strcmp (sec->name, ".preinit_array")) {
			type = R_BIN_ENTRY_TYPE_PREINIT;
		}
		if (type != -1) {
			ut8 *buf = calloc (sec->size, 1);
			if (!buf) {
				continue;
			}
			(void)r_buf_read_at (bf->buf, sec->paddr, buf, sec->size);
			if (bits == 32) {
				for (i = 0; i < sec->size; i += 4) {
					ut32 addr32 = r_read_le32 (buf + i);
					if (addr32) {
						RBinAddr *ba = newEntry (sec->paddr + i, (ut64)addr32, type, bits);
						r_list_append (ret, ba);
					}
				}
			} else {
				for (i = 0; i < sec->size; i += 8) {
					ut64 addr64 = r_read_le64 (buf + i);
					if (addr64) {
						RBinAddr *ba = newEntry (sec->paddr + i, addr64, type, bits);
						r_list_append (ret, ba);
					}
				}
			}
			free (buf);
		}
	}
	r_list_free (secs);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -348,7 +348,7 @@
 			}
 			(void)r_buf_read_at (bf->buf, sec->paddr, buf, sec->size);
 			if (bits == 32) {
-				for (i = 0; i < sec->size; i += 4) {
+				for (i = 0; (i + 3) < sec->size; i += 4) {
 					ut32 addr32 = r_read_le32 (buf + i);
 					if (addr32) {
 						RBinAddr *ba = newEntry (sec->paddr + i, (ut64)addr32, type, bits);
@@ -356,7 +356,7 @@
 					}
 				}
 			} else {
-				for (i = 0; i < sec->size; i += 8) {
+				for (i = 0; (i + 7) < sec->size; i += 8) {
 					ut64 addr64 = r_read_le64 (buf + i);
 					if (addr64) {
 						RBinAddr *ba = newEntry (sec->paddr + i, addr64, type, bits);
```
