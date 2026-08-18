# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 572_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `572_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 508-548 of the vulnerable file.

		 * nr_pages for one entry is limited to (UINT_MAX>>PAGE_SHIFT)+1,
		 * so tot_pages cannot overflow without first going negative.
		 */
		if (tot_pages < 0)
			return -EINVAL;
	}

	return tot_pages;
}

int rds_rdma_extra_size(struct rds_rdma_args *args)
{
	struct rds_iovec vec;
	struct rds_iovec __user *local_vec;
	int tot_pages = 0;
	unsigned int nr_pages;
	unsigned int i;

	local_vec = (struct rds_iovec __user *)(unsigned long) args->local_vec_addr;

	/* figure out the number of pages in the vector */
	for (i = 0; i < args->nr_local; i++) {
		if (copy_from_user(&vec, &local_vec[i],
				   sizeof(struct rds_iovec)))
			return -EFAULT;

		nr_pages = rds_pages_in_vec(&vec);
		if (nr_pages == 0)
			return -EINVAL;

		tot_pages += nr_pages;

		/*
		 * nr_pages for one entry is limited to (UINT_MAX>>PAGE_SHIFT)+1,
		 * so tot_pages cannot overflow without first going negative.
		 */
		if (tot_pages < 0)
			return -EINVAL;
	}

	return tot_pages * sizeof(struct scatterlist);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -525,6 +525,9 @@
 
 	local_vec = (struct rds_iovec __user *)(unsigned long) args->local_vec_addr;
 
+	if (args->nr_local == 0)
+		return -EINVAL;
+
 	/* figure out the number of pages in the vector */
 	for (i = 0; i < args->nr_local; i++) {
 		if (copy_from_user(&vec, &local_vec[i],
```
