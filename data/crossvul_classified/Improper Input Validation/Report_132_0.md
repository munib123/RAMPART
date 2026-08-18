# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 132_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `132_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 225-265 of the vulnerable file.

	for_each_cpu(cpu, mask) {
		struct coresight_device *csdev;

		csdev = per_cpu(csdev_src, cpu);
		if (!csdev)
			goto err;

		/*
		 * Building a path doesn't enable it, it simply builds a
		 * list of devices from source to sink that can be
		 * referenced later when the path is actually needed.
		 */
		event_data->path[cpu] = coresight_build_path(csdev, sink);
		if (IS_ERR(event_data->path[cpu]))
			goto err;
	}

	if (!sink_ops(sink)->alloc_buffer)
		goto err;

	/* Get the AUX specific data from the sink buffer */
	event_data->snk_config =
			sink_ops(sink)->alloc_buffer(sink, cpu, pages,
						     nr_pages, overwrite);
	if (!event_data->snk_config)
		goto err;

out:
	return event_data;

err:
	etm_free_aux(event_data);
	event_data = NULL;
	goto out;
}

static void etm_event_start(struct perf_event *event, int flags)
{
	int cpu = smp_processor_id();
	struct etm_event_data *event_data;
	struct perf_output_handle *handle = this_cpu_ptr(&ctx_handle);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -242,6 +242,7 @@
 	if (!sink_ops(sink)->alloc_buffer)
 		goto err;
 
+	cpu = cpumask_first(mask);
 	/* Get the AUX specific data from the sink buffer */
 	event_data->snk_config =
 			sink_ops(sink)->alloc_buffer(sink, cpu, pages,
```
