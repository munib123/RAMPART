# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1272_4
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1272_4`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1553-1575 of the vulnerable file.

fail:

	destruct(pool);

	return false;
}

struct resource_pool *dcn10_create_resource_pool(
		const struct dc_init_data *init_data,
		struct dc *dc)
{
	struct dcn10_resource_pool *pool =
		kzalloc(sizeof(struct dcn10_resource_pool), GFP_KERNEL);

	if (!pool)
		return NULL;

	if (construct(init_data->num_virtual_links, dc, pool))
		return &pool->base;

	BREAK_TO_DEBUGGER();
	return NULL;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1570,6 +1570,7 @@
 	if (construct(init_data->num_virtual_links, dc, pool))
 		return &pool->base;
 
+	kfree(pool);
 	BREAK_TO_DEBUGGER();
 	return NULL;
 }
```
