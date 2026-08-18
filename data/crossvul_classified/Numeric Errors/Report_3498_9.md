# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3498_9
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3498_9`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 5-45 of the vulnerable file.

 * The allocator synchronizes using per slab locks and only
 * uses a centralized lock to manage a pool of partial slabs.
 *
 * (C) 2007 SGI, Christoph Lameter <clameter@sgi.com>
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/bit_spinlock.h>
#include <linux/interrupt.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/mempolicy.h>
#include <linux/ctype.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#include <linux/memory.h>

/*
 * Lock order:
 *   1. slab_lock(page)
 *   2. slab->list_lock
 *
 *   The slab_lock protects operations on the object of a particular
 *   slab and its metadata in the page struct. If the slab lock
 *   has been taken then no allocations nor frees can be performed
 *   on the objects in the slab nor can the slab be added or removed
 *   from the partial or full lists since this would mean modifying
 *   the page_struct of the slab.
 *
 *   The list_lock protects the partial and full list on each node and
 *   the partial slab counter. If taken then no new slabs may be added or
 *   removed from the lists nor make the number of partial slabs be modified.
 *   (Note that the total number of slabs is an atomic value that may be
 *   modified without taking the list lock).
 *
 *   The list_lock is a centralized lock and thus we avoid taking it as
 *   much as possible. As long as SLUB does not have to handle partial
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,7 @@
 #include <linux/debugobjects.h>
 #include <linux/kallsyms.h>
 #include <linux/memory.h>
+#include <linux/math64.h>
 
 /*
  * Lock order:
@@ -3621,12 +3622,10 @@
 			len += sprintf(buf + len, "<not-available>");
 
 		if (l->sum_time != l->min_time) {
-			unsigned long remainder;
-
 			len += sprintf(buf + len, " age=%ld/%ld/%ld",
-			l->min_time,
-			div_long_long_rem(l->sum_time, l->count, &remainder),
-			l->max_time);
+				l->min_time,
+				(long)div_u64(l->sum_time, l->count),
+				l->max_time);
 		} else
 			len += sprintf(buf + len, " age=%ld",
 				l->min_time);
```
