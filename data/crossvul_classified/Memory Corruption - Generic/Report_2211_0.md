# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2211_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2211_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2488-2528 of the vulnerable file.

		else
			ss = strdup("(unknown reason)");

		applog(LOG_INFO, "JSON-RPC decode failed: %s", ss);

		free(ss);

		goto out;
	}

	sessionid = get_sessionid(res_val);
	if (!sessionid)
		applog(LOG_DEBUG, "Failed to get sessionid in initiate_stratum");
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

	cg_wlock(&pool->data_lock);
	pool->sessionid = sessionid;
	pool->nonce1 = nonce1;
	pool->n1_len = strlen(nonce1) / 2;
	free(pool->nonce1bin);
	pool->nonce1bin = (unsigned char *)calloc(pool->n1_len, 1);
	if (unlikely(!pool->nonce1bin))
		quithere(1, "Failed to calloc pool->nonce1bin");
	hex2bin(pool->nonce1bin, pool->nonce1, pool->n1_len);
	pool->n2size = n2size;
	cg_wunlock(&pool->data_lock);

	if (sessionid)
		applog(LOG_DEBUG, "%s stratum session id: %s", get_pool_name(pool), pool->sessionid);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2505,7 +2505,8 @@
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
