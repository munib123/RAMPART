# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1626_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1626_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1331-1371 of the vulnerable file.

	hlist_move_list(&unmounted, &head);

	up_write(&namespace_sem);

	if (likely(hlist_empty(&head)))
		return;

	synchronize_rcu();

	group_pin_kill(&head);
}

static inline void namespace_lock(void)
{
	down_write(&namespace_sem);
}

enum umount_tree_flags {
	UMOUNT_SYNC = 1,
	UMOUNT_PROPAGATE = 2,
};
/*
 * mount_lock must be held
 * namespace_sem must be held for write
 */
static void umount_tree(struct mount *mnt, enum umount_tree_flags how)
{
	LIST_HEAD(tmp_list);
	struct mount *p;

	if (how & UMOUNT_PROPAGATE)
		propagate_mount_unlock(mnt);

	/* Gather the mounts to umount */
	for (p = mnt; p; p = next_mnt(p, mnt)) {
		p->mnt.mnt_flags |= MNT_UMOUNT;
		list_move(&p->mnt_list, &tmp_list);
	}

	/* Hide the mounts from mnt_mounts */
	list_for_each_entry(p, &tmp_list, mnt_list) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1348,6 +1348,7 @@
 enum umount_tree_flags {
 	UMOUNT_SYNC = 1,
 	UMOUNT_PROPAGATE = 2,
+	UMOUNT_CONNECTED = 4,
 };
 /*
  * mount_lock must be held
@@ -1386,7 +1387,10 @@
 		if (how & UMOUNT_SYNC)
 			p->mnt.mnt_flags |= MNT_SYNC_UMOUNT;
 
-		disconnect = !IS_MNT_LOCKED_AND_LAZY(p);
+		disconnect = !(((how & UMOUNT_CONNECTED) &&
+				mnt_has_parent(p) &&
+				(p->mnt_parent->mnt.mnt_flags & MNT_UMOUNT)) ||
+			       IS_MNT_LOCKED_AND_LAZY(p));
 
 		pin_insert_group(&p->mnt_umount, &p->mnt_parent->mnt,
 				 disconnect ? &unmounted : NULL);
@@ -1529,7 +1533,7 @@
 				umount_mnt(p);
 			}
 		}
-		else umount_tree(mnt, 0);
+		else umount_tree(mnt, UMOUNT_CONNECTED);
 	}
 	unlock_mount_hash();
 	put_mountpoint(mp);
```
