# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 140_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `140_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1026-1066 of the vulnerable file.

}

static int bin_entry(RCore *r, int mode, ut64 laddr, int va, bool inifin) {
	char str[R_FLAG_NAME_SIZE];
	RList *entries = r_bin_get_entries (r->bin);
	RListIter *iter;
	RBinAddr *entry = NULL;
	int i = 0;
	ut64 baddr = r_bin_get_baddr (r->bin);

	if (IS_MODE_RAD (mode)) {
		r_cons_printf ("fs symbols\n");
	} else if (IS_MODE_JSON (mode)) {
		r_cons_printf ("[");
	} else if (IS_MODE_NORMAL (mode)) {
		if (inifin) {
			r_cons_printf ("[Constructors]\n");
		} else {
			r_cons_printf ("[Entrypoints]\n");
		}
	}

	r_list_foreach (entries, iter, entry) {
		ut64 paddr = entry->paddr;
		ut64 haddr = UT64_MAX;
		if (mode != R_CORE_BIN_SET) {
			if (inifin) {
				if (entry->type == R_BIN_ENTRY_TYPE_PROGRAM) {
					continue;
				}
			} else {
				if (entry->type != R_BIN_ENTRY_TYPE_PROGRAM) {
					continue;
				}
			}
		}
		switch (entry->type) {
		case R_BIN_ENTRY_TYPE_INIT:
		case R_BIN_ENTRY_TYPE_FINI:
		case R_BIN_ENTRY_TYPE_PREINIT:
			if (r->io->va && entry->paddr == entry->vaddr) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1043,6 +1043,10 @@
 		} else {
 			r_cons_printf ("[Entrypoints]\n");
 		}
+	}
+	if (r_list_length (entries) > 1024) {
+		eprintf ("Too many entrypoints (%d)\n", r_list_length (entries));
+		return false;
 	}
 
 	r_list_foreach (entries, iter, entry) {
```
