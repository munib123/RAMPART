# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1237_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1237_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 555-595 of the vulnerable file.

#define MLX5_CR_DUMP_CHUNK_SIZE 256
static int
mlx5_fw_fatal_reporter_dump(struct devlink_health_reporter *reporter,
			    struct devlink_fmsg *fmsg, void *priv_ctx)
{
	struct mlx5_core_dev *dev = devlink_health_reporter_priv(reporter);
	u32 crdump_size = dev->priv.health.crdump_size;
	u32 *cr_data;
	u32 data_size;
	u32 offset;
	int err;

	if (!mlx5_core_is_pf(dev))
		return -EPERM;

	cr_data = kvmalloc(crdump_size, GFP_KERNEL);
	if (!cr_data)
		return -ENOMEM;
	err = mlx5_crdump_collect(dev, cr_data);
	if (err)
		return err;

	if (priv_ctx) {
		struct mlx5_fw_reporter_ctx *fw_reporter_ctx = priv_ctx;

		err = mlx5_fw_reporter_ctx_pairs_put(fmsg, fw_reporter_ctx);
		if (err)
			goto free_data;
	}

	err = devlink_fmsg_arr_pair_nest_start(fmsg, "crdump_data");
	if (err)
		goto free_data;
	for (offset = 0; offset < crdump_size; offset += data_size) {
		if (crdump_size - offset < MLX5_CR_DUMP_CHUNK_SIZE)
			data_size = crdump_size - offset;
		else
			data_size = MLX5_CR_DUMP_CHUNK_SIZE;
		err = devlink_fmsg_binary_put(fmsg, (char *)cr_data + offset,
					      data_size);
		if (err)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -572,7 +572,7 @@
 		return -ENOMEM;
 	err = mlx5_crdump_collect(dev, cr_data);
 	if (err)
-		return err;
+		goto free_data;
 
 	if (priv_ctx) {
 		struct mlx5_fw_reporter_ctx *fw_reporter_ctx = priv_ctx;
```
