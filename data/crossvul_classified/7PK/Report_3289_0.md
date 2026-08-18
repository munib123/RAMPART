# CrossVul Fix Pair: 7PK in c
**Pair ID:** 3289_0
**Vulnerability Class:** 7PK
**CWE:** CWE-388
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3289_0`)

## Vulnerability Information & PoC

## Description
7PK - Errors

## Vulnerable Code
```c
Lines 1512-1552 of the vulnerable file.

	if (nmask)
		nm = compat_alloc_user_space(alloc_size);

	err = sys_get_mempolicy(policy, nm, nr_bits+1, addr, flags);

	if (!err && nmask) {
		unsigned long copy_size;
		copy_size = min_t(unsigned long, sizeof(bm), alloc_size);
		err = copy_from_user(bm, nm, copy_size);
		/* ensure entire bitmap is zeroed */
		err |= clear_user(nmask, ALIGN(maxnode-1, 8) / 8);
		err |= compat_put_bitmap(nmask, bm, nr_bits);
	}

	return err;
}

COMPAT_SYSCALL_DEFINE3(set_mempolicy, int, mode, compat_ulong_t __user *, nmask,
		       compat_ulong_t, maxnode)
{
	long err = 0;
	unsigned long __user *nm = NULL;
	unsigned long nr_bits, alloc_size;
	DECLARE_BITMAP(bm, MAX_NUMNODES);

	nr_bits = min_t(unsigned long, maxnode-1, MAX_NUMNODES);
	alloc_size = ALIGN(nr_bits, BITS_PER_LONG) / 8;

	if (nmask) {
		err = compat_get_bitmap(bm, nmask, nr_bits);
		nm = compat_alloc_user_space(alloc_size);
		err |= copy_to_user(nm, bm, alloc_size);
	}

	if (err)
		return -EFAULT;

	return sys_set_mempolicy(mode, nm, nr_bits+1);
}

COMPAT_SYSCALL_DEFINE6(mbind, compat_ulong_t, start, compat_ulong_t, len,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1529,7 +1529,6 @@
 COMPAT_SYSCALL_DEFINE3(set_mempolicy, int, mode, compat_ulong_t __user *, nmask,
 		       compat_ulong_t, maxnode)
 {
-	long err = 0;
 	unsigned long __user *nm = NULL;
 	unsigned long nr_bits, alloc_size;
 	DECLARE_BITMAP(bm, MAX_NUMNODES);
@@ -1538,13 +1537,12 @@
 	alloc_size = ALIGN(nr_bits, BITS_PER_LONG) / 8;
 
 	if (nmask) {
-		err = compat_get_bitmap(bm, nmask, nr_bits);
+		if (compat_get_bitmap(bm, nmask, nr_bits))
+			return -EFAULT;
 		nm = compat_alloc_user_space(alloc_size);
-		err |= copy_to_user(nm, bm, alloc_size);
-	}
-
-	if (err)
-		return -EFAULT;
+		if (copy_to_user(nm, bm, alloc_size))
+			return -EFAULT;
+	}
 
 	return sys_set_mempolicy(mode, nm, nr_bits+1);
 }
@@ -1553,7 +1551,6 @@
 		       compat_ulong_t, mode, compat_ulong_t __user *, nmask,
 		       compat_ulong_t, maxnode, compat_ulong_t, flags)
 {
-	long err = 0;
 	unsigned long __user *nm = NULL;
 	unsigned long nr_bits, alloc_size;
 	nodemask_t bm;
@@ -1562,13 +1559,12 @@
 	alloc_size = ALIGN(nr_bits, BITS_PER_LONG) / 8;
 
 	if (nmask) {
-		err = compat_get_bitmap(nodes_addr(bm), nmask, nr_bits);
+		if (compat_get_bitmap(nodes_addr(bm), nmask, nr_bits))
+			return -EFAULT;
 		nm = compat_alloc_user_space(alloc_size);
-		err |= copy_to_user(nm, nodes_addr(bm), alloc_size);
-	}
-
-	if (err)
-		return -EFAULT;
+		if (copy_to_user(nm, nodes_addr(bm), alloc_size))
+			return -EFAULT;
+	}
 
 	return sys_mbind(start, len, mode, nm, nr_bits+1, flags);
 }
```
