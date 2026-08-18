# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4701_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4701_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 207-247 of the vulnerable file.

	IPADDR *own_ip = NULL;
	const char *errmsg;
	char *errmsg2;
	char ipaddr[MAX_IP_LEN];
        int port;

	g_return_if_fail(ip != NULL || unix_socket != NULL);

	signal_emit("server connecting", 2, server, ip);

	if (server->connrec->no_connect)
		return;

	if (ip != NULL) {
		own_ip = ip == NULL ? NULL :
			(IPADDR_IS_V6(ip) ? server->connrec->own_ip6 :
			 server->connrec->own_ip4);
		port = server->connrec->proxy != NULL ?
			server->connrec->proxy_port : server->connrec->port;
		handle = server->connrec->use_ssl ?
			net_connect_ip_ssl(ip, port, own_ip, server->connrec->ssl_cert, server->connrec->ssl_pkey,
server->connrec->ssl_cafile, server->connrec->ssl_capath, server->connrec->ssl_verify) :
			net_connect_ip(ip, port, own_ip);
	} else {
		handle = net_connect_unix(unix_socket);
	}

	if (handle == NULL) {
		/* failed */
		errmsg = g_strerror(errno);
		errmsg2 = NULL;
		if (errno == EADDRNOTAVAIL) {
			if (own_ip != NULL) {
				/* show the IP which is causing the error */
				net_ip2host(own_ip, ipaddr);
				errmsg2 = g_strconcat(errmsg, ": ", ipaddr, NULL);
			}
			server->no_reconnect = TRUE;
		}
		if (server->connrec->use_ssl && errno == ENOSYS)
			server->no_reconnect = TRUE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,7 +224,7 @@
 		port = server->connrec->proxy != NULL ?
 			server->connrec->proxy_port : server->connrec->port;
 		handle = server->connrec->use_ssl ?
-			net_connect_ip_ssl(ip, port, own_ip, server->connrec->ssl_cert, server->connrec->ssl_pkey,
+			net_connect_ip_ssl(ip, port, server->connrec->address, own_ip, server->connrec->ssl_cert, server->connrec->ssl_pkey,
 server->connrec->ssl_cafile, server->connrec->ssl_capath, server->connrec->ssl_verify) :
 			net_connect_ip(ip, port, own_ip);
 	} else {
```
