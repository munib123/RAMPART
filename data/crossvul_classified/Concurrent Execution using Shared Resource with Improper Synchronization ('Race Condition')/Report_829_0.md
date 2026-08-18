# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 829_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `829_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 976-1016 of the vulnerable file.

			mm = priv->vma->vm_mm;
			ret = mmget_not_zero(mm);
			if (!ret) {
				list_del_init(&priv->list);
				mm = NULL;
				continue;
			}
			break;
		}
		mutex_unlock(&ufile->umap_lock);
		if (!mm)
			return;

		/*
		 * The umap_lock is nested under mmap_sem since it used within
		 * the vma_ops callbacks, so we have to clean the list one mm
		 * at a time to get the lock ordering right. Typically there
		 * will only be one mm, so no big deal.
		 */
		down_write(&mm->mmap_sem);
		mutex_lock(&ufile->umap_lock);
		list_for_each_entry_safe (priv, next_priv, &ufile->umaps,
					  list) {
			struct vm_area_struct *vma = priv->vma;

			if (vma->vm_mm != mm)
				continue;
			list_del_init(&priv->list);

			zap_vma_ptes(vma, vma->vm_start,
				     vma->vm_end - vma->vm_start);
			vma->vm_flags &= ~(VM_SHARED | VM_MAYSHARE);
		}
		mutex_unlock(&ufile->umap_lock);
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
}

/*
 * ib_uverbs_open() does not need the BKL:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -993,6 +993,8 @@
 		 * will only be one mm, so no big deal.
 		 */
 		down_write(&mm->mmap_sem);
+		if (!mmget_still_valid(mm))
+			goto skip_mm;
 		mutex_lock(&ufile->umap_lock);
 		list_for_each_entry_safe (priv, next_priv, &ufile->umaps,
 					  list) {
@@ -1007,6 +1009,7 @@
 			vma->vm_flags &= ~(VM_SHARED | VM_MAYSHARE);
 		}
 		mutex_unlock(&ufile->umap_lock);
+	skip_mm:
 		up_write(&mm->mmap_sem);
 		mmput(mm);
 	}
```
