# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3464_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3464_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1318-1358 of the vulnerable file.


	list_for_each (item, frags) {
		f = list_entry (item, struct frag, list);
		if (f->group == group)
			goto found;
	}

	f = kmalloc (sizeof (*f) + size*num, GFP_KERNEL);
	if (!f) {
		ldm_crit ("Out of memory.");
		return false;
	}

	f->group = group;
	f->num   = num;
	f->rec   = rec;
	f->map   = 0xFF << num;

	list_add_tail (&f->list, frags);
found:
	if (f->map & (1 << rec)) {
		ldm_error ("Duplicate VBLK, part %d.", rec);
		f->map &= 0x7F;			/* Mark the group as broken */
		return false;
	}

	f->map |= (1 << rec);

	data += VBLK_SIZE_HEAD;
	size -= VBLK_SIZE_HEAD;

	memcpy (f->data+rec*(size-VBLK_SIZE_HEAD)+VBLK_SIZE_HEAD, data, size);

	return true;
}

/**
 * ldm_frag_free - Free a linked list of VBLK fragments
 * @list:  Linked list of fragments
 *
 * Free a linked list of VBLK fragments
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1335,6 +1335,11 @@
 
 	list_add_tail (&f->list, frags);
 found:
+	if (rec >= f->num) {
+		ldm_error("REC value (%d) exceeds NUM value (%d)", rec, f->num);
+		return false;
+	}
+
 	if (f->map & (1 << rec)) {
 		ldm_error ("Duplicate VBLK, part %d.", rec);
 		f->map &= 0x7F;			/* Mark the group as broken */
```
