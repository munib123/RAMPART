# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2208_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2208_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1701-1743 of the vulnerable file.

	hex2bin(pool->nonce1bin, pool->nonce1, pool->n1_len);
	pool->n2size = n2size;
	cg_wunlock(&pool->data_lock);

	applog(LOG_NOTICE, "%s extranonce change requested", get_pool_name(pool));

	return true;
}

static void __suspend_stratum(struct pool *pool)
{
	clear_sockbuf(pool);
	pool->stratum_active = pool->stratum_notify = false;
	if (pool->sock)
		CLOSESOCKET(pool->sock);
	pool->sock = 0;
}

static bool parse_reconnect(struct pool *pool, json_t *val)
{
	char *sockaddr_url, *stratum_port, *tmp;
	char *url, *port, address[256];

	if (opt_disable_client_reconnect) {
		applog(LOG_WARNING, "Stratum client.reconnect forbidden, aborting.");
		return false;
	}

	memset(address, 0, 255);
	url = (char *)json_string_value(json_array_get(val, 0));
	if (!url)
		url = pool->sockaddr_url;

	port = (char *)json_string_value(json_array_get(val, 1));
	if (!port)
		port = pool->stratum_port;

	sprintf(address, "%s:%s", url, port);

	if (!extract_sockaddr(address, &sockaddr_url, &stratum_port))
		return false;

	applog(LOG_NOTICE, "Reconnect requested from %s to %s", get_pool_name(pool), address);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1718,15 +1718,14 @@
 
 static bool parse_reconnect(struct pool *pool, json_t *val)
 {
-	char *sockaddr_url, *stratum_port, *tmp;
+	if (opt_disable_client_reconnect) {
+		applog(LOG_WARNING, "Stratum client.reconnect received but is disabled, not reconnecting.");
+		return false;
+	}
+
 	char *url, *port, address[256];
-
-	if (opt_disable_client_reconnect) {
-		applog(LOG_WARNING, "Stratum client.reconnect forbidden, aborting.");
-		return false;
-	}
-
-	memset(address, 0, 255);
+	char *sockaddr_url, *stratum_port, *tmp; /* Tempvars. */
+
 	url = (char *)json_string_value(json_array_get(val, 0));
 	if (!url)
 		url = pool->sockaddr_url;
@@ -1735,8 +1734,7 @@
 	if (!port)
 		port = pool->stratum_port;
 
-	sprintf(address, "%s:%s", url, port);
-
+	snprintf(address, sizeof(address), "%s:%s", url, port);
 	if (!extract_sockaddr(address, &sockaddr_url, &stratum_port))
 		return false;
 
```
