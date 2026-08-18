# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1217_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1217_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 135-176 of the vulnerable file.

	char *string;
	int ret;

	string = kzalloc(count, GFP_KERNEL);
	if (!string)
		return -ENOMEM;

	size = simple_write_to_buffer(string, count, ppos, buffer, count);
	ret = size;

#if IS_ENABLED(CONFIG_SND_SOC_SOF_DEBUG_IPC_FLOOD_TEST)
	/*
	 * write op is only supported for ipc_flood_count or
	 * ipc_flood_duration_ms debugfs entries atm.
	 * ipc_flood_count floods the DSP with the number of IPC's specified.
	 * ipc_duration_ms test floods the DSP for the time specified
	 * in the debugfs entry.
	 */
	dentry = file->f_path.dentry;
	if (strcmp(dentry->d_name.name, "ipc_flood_count") &&
	    strcmp(dentry->d_name.name, "ipc_flood_duration_ms"))
		return -EINVAL;

	if (!strcmp(dentry->d_name.name, "ipc_flood_duration_ms"))
		flood_duration_test = true;

	/* test completion criterion */
	if (flood_duration_test)
		ret = kstrtoul(string, 0, &ipc_duration_ms);
	else
		ret = kstrtoul(string, 0, &ipc_count);
	if (ret < 0)
		goto out;

	/* limit max duration/ipc count for flood test */
	if (flood_duration_test) {
		if (!ipc_duration_ms) {
			ret = size;
			goto out;
		}

		/* find the minimum. min() is not used to avoid warnings */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,8 +152,10 @@
 	 */
 	dentry = file->f_path.dentry;
 	if (strcmp(dentry->d_name.name, "ipc_flood_count") &&
-	    strcmp(dentry->d_name.name, "ipc_flood_duration_ms"))
-		return -EINVAL;
+	    strcmp(dentry->d_name.name, "ipc_flood_duration_ms")) {
+		ret = -EINVAL;
+		goto out;
+	}
 
 	if (!strcmp(dentry->d_name.name, "ipc_flood_duration_ms"))
 		flood_duration_test = true;
```
