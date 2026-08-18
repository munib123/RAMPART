# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2210_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2210_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1688-1728 of the vulnerable file.


		applog(LOG_INFO, "JSON-RPC decode failed: %s", ss);

		free(ss);

		goto out;
	}

	sessionid = json_array_string(json_array_get(res_val, 0), 1);
	if (!sessionid) {
		applog(LOG_INFO, "Failed to get sessionid in initiate_stratum");
		goto out;
	}
	nonce1 = json_array_string(res_val, 1);
	if (!nonce1) {
		applog(LOG_INFO, "Failed to get nonce1 in initiate_stratum");
		free(sessionid);
		goto out;
	}
	n2size = json_integer_value(json_array_get(res_val, 2));
	if (!n2size) {
		applog(LOG_INFO, "Failed to get n2size in initiate_stratum");
		free(sessionid);
		free(nonce1);
		goto out;
	}

	mutex_lock(&pool->pool_lock);
	pool->sessionid = sessionid;
	free(pool->nonce1);
	pool->nonce1 = nonce1;
	pool->n1_len = strlen(nonce1) / 2;
	pool->n2size = n2size;
	mutex_unlock(&pool->pool_lock);

	applog(LOG_DEBUG, "Pool %d stratum session id: %s", pool->pool_no, pool->sessionid);

	ret = true;
out:
	if (val)
		json_decref(val);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1705,7 +1705,8 @@
 		goto out;
 	}
 	n2size = json_integer_value(json_array_get(res_val, 2));
-	if (!n2size) {
+	if (n2size < 1)
+	{
 		applog(LOG_INFO, "Failed to get n2size in initiate_stratum");
 		free(sessionid);
 		free(nonce1);
```
