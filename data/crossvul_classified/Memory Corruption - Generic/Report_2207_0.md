# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2207_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2207_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 985-1025 of the vulnerable file.

		url_begin += 2;

	/* Look for numeric ipv6 entries */
	ipv6_begin = strstr(url_begin, "[");
	ipv6_end = strstr(url_begin, "]");
	if (ipv6_begin && ipv6_end && ipv6_end > ipv6_begin)
		url_end = strstr(ipv6_end, ":");
	else
		url_end = strstr(url_begin, ":");
	if (url_end) {
		url_len = url_end - url_begin;
		port_len = strlen(url_begin) - url_len - 1;
		if (port_len < 1)
			return false;
		port_start = url_end + 1;
	} else
		url_len = strlen(url_begin);

	if (url_len < 1)
		return false;

	sprintf(url_address, "%.*s", url_len, url_begin);

	if (port_len)
		snprintf(port, 6, "%.*s", port_len, port_start);
	else
		strcpy(port, "80");

	free(pool->stratum_port);
	pool->stratum_port = strdup(port);
	free(pool->sockaddr_url);
	pool->sockaddr_url = strdup(url_address);

	return true;
}

/* Send a single command across a socket, appending \n to it. This should all
 * be done under stratum lock except when first establishing the socket */
static bool __stratum_send(struct pool *pool, char *s, ssize_t len)
{
	SOCKETTYPE sock = pool->sock;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1002,6 +1002,13 @@
 
 	if (url_len < 1)
 		return false;
+	
+	if (url_len >= sizeof(url_address))
+	{
+		applog(LOG_WARNING, "%s: Truncating overflowed address '%.*s'",
+		       __func__, url_len, url_begin);
+		url_len = sizeof(url_address) - 1;
+	}
 
 	sprintf(url_address, "%.*s", url_len, url_begin);
 
```
