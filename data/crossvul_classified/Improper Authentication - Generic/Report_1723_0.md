# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 1723_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1723_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 66-106 of the vulnerable file.

	if (auth_type == AUTH_MD5) {
		saltlen = 4;
		get_random_bytes((void*)client->tmp_login_salt, saltlen);
	} else if (auth_type == AUTH_PLAIN) {
		/* nothing to do */
	} else {
		return false;
	}

	SEND_generic(res, client, 'R', "ib", auth_type, client->tmp_login_salt, saltlen);
	if (!res)
		disconnect_client(client, false, "failed to send auth req");
	return res;
}

static void start_auth_request(PgSocket *client, const char *username)
{
	int res;
	PktBuf *buf;

	client->auth_user = client->db->auth_user;
	/* have to fetch user info from db */
	client->pool = get_pool(client->db, client->db->auth_user);
	if (!find_server(client)) {
		client->wait_for_user_conn = true;
		return;
	}
	slog_noise(client, "Doing auth_conn query");
	client->wait_for_user_conn = false;
	client->wait_for_user = true;
	if (!sbuf_pause(&client->sbuf)) {
		release_server(client->link);
		disconnect_client(client, true, "pause failed");
		return;
	}
	client->link->ready = 0;

	res = 0;
	buf = pktbuf_dynamic(512);
	if (buf) {
		pktbuf_write_ExtQuery(buf, cf_auth_query, 1, username);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,7 +83,6 @@
 	int res;
 	PktBuf *buf;
 
-	client->auth_user = client->db->auth_user;
 	/* have to fetch user info from db */
 	client->pool = get_pool(client->db, client->db->auth_user);
 	if (!find_server(client)) {
```
