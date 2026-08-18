# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in c
**Pair ID:** 612_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `612_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```c
Lines 519-559 of the vulnerable file.

	return r;
}

UNCURL_EXPORT int32_t uncurl_ws_accept(struct uncurl_conn *ucc, char **origins, int32_t n_origins)
{
	int32_t e;

	//wait for the client's request header
	e = uncurl_read_header(ucc);
	if (e != UNCURL_OK) return e;

	//set obligatory headers
	uncurl_set_header_str(ucc, "Upgrade", "websocket");
	uncurl_set_header_str(ucc, "Connection", "Upgrade");

	//check the origin header against our whitelist
	char *origin = NULL;
	e = uncurl_get_header_str(ucc, "Origin", &origin);
	if (e != UNCURL_OK) return e;

	bool origin_ok = false;
	for (int32_t x = 0; x < n_origins; x++)
		if (strstr(origin, origins[x])) {origin_ok = true; break;}

	if (!origin_ok) return UNCURL_WS_ERR_ORIGIN;

	//read the key and set a compliant response header
	char *sec_key = NULL;
	e = uncurl_get_header_str(ucc, "Sec-WebSocket-Key", &sec_key);
	if (e != UNCURL_OK) return e;

	char *accept_key = ws_create_accept_key(sec_key);
	uncurl_set_header_str(ucc, "Sec-WebSocket-Accept", accept_key);
	free(accept_key);

	//write the response header
	e = uncurl_write_header(ucc, "101", "Switching Protocols", UNCURL_RESPONSE);
	if (e != UNCURL_OK) return e;

	//server does not send masked messages
	ucc->ws_mask = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -536,9 +536,12 @@
 	e = uncurl_get_header_str(ucc, "Origin", &origin);
 	if (e != UNCURL_OK) return e;
 
+	//the substring MUST came at the end of the origin header, thus a strstr AND a strcmp
 	bool origin_ok = false;
-	for (int32_t x = 0; x < n_origins; x++)
-		if (strstr(origin, origins[x])) {origin_ok = true; break;}
+	for (int32_t x = 0; x < n_origins; x++) {
+		char *match = strstr(origin, origins[x]);
+		if (match && !strcmp(match, origins[x])) {origin_ok = true; break;}
+	}
 
 	if (!origin_ok) return UNCURL_WS_ERR_ORIGIN;
 
```
