# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 635_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `635_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 166-206 of the vulnerable file.

		ret = -EFAULT;
	}

	return ret;
}

static int __rds_rdma_map(struct rds_sock *rs, struct rds_get_mr_args *args,
				u64 *cookie_ret, struct rds_mr **mr_ret)
{
	struct rds_mr *mr = NULL, *found;
	unsigned int nr_pages;
	struct page **pages = NULL;
	struct scatterlist *sg;
	void *trans_private;
	unsigned long flags;
	rds_rdma_cookie_t cookie;
	unsigned int nents;
	long i;
	int ret;

	if (rs->rs_bound_addr == 0) {
		ret = -ENOTCONN; /* XXX not a great errno */
		goto out;
	}

	if (!rs->rs_transport->get_mr) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	nr_pages = rds_pages_in_vec(&args->vec);
	if (nr_pages == 0) {
		ret = -EINVAL;
		goto out;
	}

	/* Restrict the size of mr irrespective of underlying transport
	 * To account for unaligned mr regions, subtract one from nr_pages
	 */
	if ((nr_pages - 1) > (RDS_MAX_MSG_SIZE >> PAGE_SHIFT)) {
		ret = -EMSGSIZE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -183,7 +183,7 @@
 	long i;
 	int ret;
 
-	if (rs->rs_bound_addr == 0) {
+	if (rs->rs_bound_addr == 0 || !rs->rs_transport) {
 		ret = -ENOTCONN; /* XXX not a great errno */
 		goto out;
 	}
```
