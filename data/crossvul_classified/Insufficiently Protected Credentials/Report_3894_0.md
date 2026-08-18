# CrossVul Fix Pair: Insufficiently Protected Credentials in c
**Pair ID:** 3894_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3894_0`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```c
Lines 340-381 of the vulnerable file.

	if (!quiet)
		warning(_("url contains a newline in its %s component: %s"),
			name, url);
	return -1;
}

int credential_from_url_gently(struct credential *c, const char *url,
			       int quiet)
{
	const char *at, *colon, *cp, *slash, *host, *proto_end;

	credential_clear(c);

	/*
	 * Match one of:
	 *   (1) proto://<host>/...
	 *   (2) proto://<user>@<host>/...
	 *   (3) proto://<user>:<pass>@<host>/...
	 */
	proto_end = strstr(url, "://");
	if (!proto_end)
		return 0;
	cp = proto_end + 3;
	at = strchr(cp, '@');
	colon = strchr(cp, ':');
	slash = strchrnul(cp, '/');

	if (!at || slash <= at) {
		/* Case (1) */
		host = cp;
	}
	else if (!colon || at <= colon) {
		/* Case (2) */
		c->username = url_decode_mem(cp, at - cp);
		host = at + 1;
	} else {
		/* Case (3) */
		c->username = url_decode_mem(cp, colon - cp);
		c->password = url_decode_mem(colon + 1, at - (colon + 1));
		host = at + 1;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -357,8 +357,11 @@
 	 *   (3) proto://<user>:<pass>@<host>/...
 	 */
 	proto_end = strstr(url, "://");
-	if (!proto_end)
-		return 0;
+	if (!proto_end) {
+		if (!quiet)
+			warning(_("url has no scheme: %s"), url);
+		return -1;
+	}
 	cp = proto_end + 3;
 	at = strchr(cp, '@');
 	colon = strchr(cp, ':');
```
