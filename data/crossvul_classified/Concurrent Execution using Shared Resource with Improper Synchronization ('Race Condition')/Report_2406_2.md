# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 2406_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2406_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 3-46 of the vulnerable file.

 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include "ctree.h"
#include "disk-io.h"
#include "hash.h"
#include "transaction.h"

static struct btrfs_dir_item *btrfs_match_dir_item_name(struct btrfs_root *root,
			      struct btrfs_path *path,
			      const char *name, int name_len);

/*
 * insert a name into a directory, doing overflow properly if there is a hash
 * collision.  data_size indicates how big the item inserted should be.  On
 * success a struct btrfs_dir_item pointer is returned, otherwise it is
 * an ERR_PTR.
 *
 * The name is not copied into the dir item, you have to do that yourself.
 */
static struct btrfs_dir_item *insert_with_overflow(struct btrfs_trans_handle
						   *trans,
						   struct btrfs_root *root,
						   struct btrfs_path *path,
						   struct btrfs_key *cpu_key,
						   u32 data_size,
						   const char *name,
						   int name_len)
{
	int ret;
	char *ptr;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,10 +21,6 @@
 #include "hash.h"
 #include "transaction.h"
 
-static struct btrfs_dir_item *btrfs_match_dir_item_name(struct btrfs_root *root,
-			      struct btrfs_path *path,
-			      const char *name, int name_len);
-
 /*
  * insert a name into a directory, doing overflow properly if there is a hash
  * collision.  data_size indicates how big the item inserted should be.  On
@@ -383,9 +379,9 @@
  * this walks through all the entries in a dir item and finds one
  * for a specific name.
  */
-static struct btrfs_dir_item *btrfs_match_dir_item_name(struct btrfs_root *root,
-			      struct btrfs_path *path,
-			      const char *name, int name_len)
+struct btrfs_dir_item *btrfs_match_dir_item_name(struct btrfs_root *root,
+						 struct btrfs_path *path,
+						 const char *name, int name_len)
 {
 	struct btrfs_dir_item *dir_item;
 	unsigned long name_ptr;
```
