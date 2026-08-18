# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1267_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1267_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1381-1421 of the vulnerable file.

		rc = bnxt_re_init_user_srq(rdev, pd, srq, udata);
		if (rc)
			goto fail;
	}

	rc = bnxt_qplib_create_srq(&rdev->qplib_res, &srq->qplib_srq);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Create HW SRQ failed!");
		goto fail;
	}

	if (udata) {
		struct bnxt_re_srq_resp resp;

		resp.srqid = srq->qplib_srq.id;
		rc = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (rc) {
			dev_err(rdev_to_dev(rdev), "SRQ copy to udata failed!");
			bnxt_qplib_destroy_srq(&rdev->qplib_res,
					       &srq->qplib_srq);
			goto exit;
		}
	}
	if (nq)
		nq->budget++;
	atomic_inc(&rdev->srq_count);

	return 0;

fail:
	ib_umem_release(srq->umem);
exit:
	return rc;
}

int bnxt_re_modify_srq(struct ib_srq *ib_srq, struct ib_srq_attr *srq_attr,
		       enum ib_srq_attr_mask srq_attr_mask,
		       struct ib_udata *udata)
{
	struct bnxt_re_srq *srq = container_of(ib_srq, struct bnxt_re_srq,
					       ib_srq);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1398,7 +1398,7 @@
 			dev_err(rdev_to_dev(rdev), "SRQ copy to udata failed!");
 			bnxt_qplib_destroy_srq(&rdev->qplib_res,
 					       &srq->qplib_srq);
-			goto exit;
+			goto fail;
 		}
 	}
 	if (nq)
```
