# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1235_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1235_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 447-487 of the vulnerable file.


	err = mlx5_cqwq_create(mdev, &wqp, temp_cqc, &conn->cq.wq,
			       &conn->cq.wq_ctrl);
	if (err)
		return err;

	for (i = 0; i < mlx5_cqwq_get_size(&conn->cq.wq); i++) {
		cqe = mlx5_cqwq_get_wqe(&conn->cq.wq, i);
		cqe->op_own = MLX5_CQE_INVALID << 4 | MLX5_CQE_OWNER_MASK;
	}

	inlen = MLX5_ST_SZ_BYTES(create_cq_in) +
		sizeof(u64) * conn->cq.wq_ctrl.buf.npages;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_cqwq;
	}

	err = mlx5_vector2eqn(mdev, smp_processor_id(), &eqn, &irqn);
	if (err)
		goto err_cqwq;

	cqc = MLX5_ADDR_OF(create_cq_in, in, cq_context);
	MLX5_SET(cqc, cqc, log_cq_size, ilog2(cq_size));
	MLX5_SET(cqc, cqc, c_eqn, eqn);
	MLX5_SET(cqc, cqc, uar_page, fdev->conn_res.uar->index);
	MLX5_SET(cqc, cqc, log_page_size, conn->cq.wq_ctrl.buf.page_shift -
			   MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET64(cqc, cqc, dbr_addr, conn->cq.wq_ctrl.db.dma);

	pas = (__be64 *)MLX5_ADDR_OF(create_cq_in, in, pas);
	mlx5_fill_page_frag_array(&conn->cq.wq_ctrl.buf, pas);

	err = mlx5_core_create_cq(mdev, &conn->cq.mcq, in, inlen, out, sizeof(out));
	kvfree(in);

	if (err)
		goto err_cqwq;

	conn->cq.mcq.cqe_sz     = 64;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -464,8 +464,10 @@
 	}
 
 	err = mlx5_vector2eqn(mdev, smp_processor_id(), &eqn, &irqn);
-	if (err)
+	if (err) {
+		kvfree(in);
 		goto err_cqwq;
+	}
 
 	cqc = MLX5_ADDR_OF(create_cq_in, in, cq_context);
 	MLX5_SET(cqc, cqc, log_cq_size, ilog2(cq_size));
```
