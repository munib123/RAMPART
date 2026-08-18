# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1234_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1234_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 540-580 of the vulnerable file.

		return -EINVAL;
	}

	render = kcalloc(1, sizeof(*render), GFP_KERNEL);
	if (!render)
		return -ENOMEM;

	render->start = args->rcl_start;
	render->end = args->rcl_end;
	INIT_LIST_HEAD(&render->unref_list);

	ret = v3d_job_init(v3d, file_priv, &render->base,
			   v3d_render_job_free, args->in_sync_rcl);
	if (ret) {
		kfree(render);
		return ret;
	}

	if (args->bcl_start != args->bcl_end) {
		bin = kcalloc(1, sizeof(*bin), GFP_KERNEL);
		if (!bin)
			return -ENOMEM;

		ret = v3d_job_init(v3d, file_priv, &bin->base,
				   v3d_job_free, args->in_sync_bcl);
		if (ret) {
			v3d_job_put(&render->base);
			return ret;
		}

		bin->start = args->bcl_start;
		bin->end = args->bcl_end;
		bin->qma = args->qma;
		bin->qms = args->qms;
		bin->qts = args->qts;
		bin->render = render;
	}

	ret = v3d_lookup_bos(dev, file_priv, &render->base,
			     args->bo_handles, args->bo_handle_count);
	if (ret)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -557,13 +557,16 @@
 
 	if (args->bcl_start != args->bcl_end) {
 		bin = kcalloc(1, sizeof(*bin), GFP_KERNEL);
-		if (!bin)
+		if (!bin) {
+			v3d_job_put(&render->base);
 			return -ENOMEM;
+		}
 
 		ret = v3d_job_init(v3d, file_priv, &bin->base,
 				   v3d_job_free, args->in_sync_bcl);
 		if (ret) {
 			v3d_job_put(&render->base);
+			kfree(bin);
 			return ret;
 		}
 
```
