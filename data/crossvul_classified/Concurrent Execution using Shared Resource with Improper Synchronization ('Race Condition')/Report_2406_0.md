# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 2406_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2406_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 2922-2962 of the vulnerable file.

				BUG_ON(err > 0);
				if (err) {
					ret = err;
					goto done;
				}
			}
			if (!p->search_for_split)
				unlock_up(p, level, lowest_unlock,
					  min_write_lock_level, &write_lock_level);
			goto done;
		}
	}
	ret = 1;
done:
	/*
	 * we don't really know what they plan on doing with the path
	 * from here on, so for now just mark it as blocking
	 */
	if (!p->leave_spinning)
		btrfs_set_path_blocking(p);
	if (ret < 0)
		btrfs_release_path(p);
	return ret;
}

/*
 * Like btrfs_search_slot, this looks for a key in the given tree. It uses the
 * current state of the tree together with the operations recorded in the tree
 * modification log to search for the key in a previous version of this tree, as
 * denoted by the time_seq parameter.
 *
 * Naturally, there is no support for insert, delete or cow operations.
 *
 * The resulting path and return value will be set up as if we called
 * btrfs_search_slot at that point in time with ins_len and cow both set to 0.
 */
int btrfs_search_old_slot(struct btrfs_root *root, struct btrfs_key *key,
			  struct btrfs_path *p, u64 time_seq)
{
	struct extent_buffer *b;
	int slot;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2939,7 +2939,7 @@
 	 */
 	if (!p->leave_spinning)
 		btrfs_set_path_blocking(p);
-	if (ret < 0)
+	if (ret < 0 && !p->skip_release_on_error)
 		btrfs_release_path(p);
 	return ret;
 }
```
