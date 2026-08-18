# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2861_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2861_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 57-97 of the vulnerable file.

		*ok = 0;
	}
	item = ht_find (f->ht_name, name, NULL);
	if (item) {
		// NOTE: to avoid warning infinite loop here we avoid recursivity
		if (item->alias) {
			return 0LL;
		}
		if (ok) {
			*ok = 1;
		}
		return item->offset;
	}
	return 0LL;
}

/* return the list of flag at the nearest position.
	dir == -1 -> result <= off
	dir == 0 ->  result == off
	dir == 1 ->  result >= off*/
static  RFlagsAtOffset* r_flag_get_nearest_list(RFlag *f, ut64 off, int dir) {
	RFlagsAtOffset *flags = NULL;
	RFlagsAtOffset key;
	key.off = off;
	if (dir >= 0) {
		flags = r_skiplist_get_geq (f->by_off, &key);
	} else {
		flags = r_skiplist_get_leq (f->by_off, &key);
	}
	if (dir == 0 && flags && flags->off != off) {
		return NULL;
	}
	return flags;
}

static void remove_offsetmap(RFlag *f, RFlagItem *item) {
	RFlagsAtOffset *flags = r_flag_get_nearest_list (f, item->offset, 0);
	if (flags) {
		r_list_delete_data (flags->flags, item);
		if (r_list_empty (flags->flags)) {
			r_skiplist_delete (f->by_off, flags);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,7 +74,7 @@
 	dir == -1 -> result <= off
 	dir == 0 ->  result == off
 	dir == 1 ->  result >= off*/
-static  RFlagsAtOffset* r_flag_get_nearest_list(RFlag *f, ut64 off, int dir) {
+static RFlagsAtOffset* r_flag_get_nearest_list(RFlag *f, ut64 off, int dir) {
 	RFlagsAtOffset *flags = NULL;
 	RFlagsAtOffset key;
 	key.off = off;
```
