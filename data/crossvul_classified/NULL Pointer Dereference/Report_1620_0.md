# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1620_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1620_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 245-285 of the vulnerable file.


		if (!decide_startup_pool(client, pkt))
			return false;

		if (client->pool->db->admin) {
			if (!admin_pre_login(client))
				return false;
		}

		if (cf_auth_type <= AUTH_TRUST || client->own_user) {
			if (!finish_client_login(client))
				return false;
		} else {
			if (!send_client_authreq(client)) {
				disconnect_client(client, false, "failed to send auth req");
				return false;
			}
		}
		break;
	case 'p':		/* PasswordMessage */
		/* haven't requested it */
		if (cf_auth_type <= AUTH_TRUST) {
			disconnect_client(client, true, "unrequested passwd pkt");
			return false;
		}

		ok = mbuf_get_string(&pkt->data, &passwd);
		if (ok && check_client_passwd(client, passwd)) {
			if (!finish_client_login(client))
				return false;
		} else {
			disconnect_client(client, true, "Auth failed");
			return false;
		}
		break;
	case PKT_CANCEL:
		if (mbuf_avail_for_read(&pkt->data) == BACKENDKEY_LEN
		    && mbuf_get_bytes(&pkt->data, BACKENDKEY_LEN, &key))
		{
			memcpy(client->cancel_key, key, BACKENDKEY_LEN);
			accept_cancel_request(client);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -262,6 +262,12 @@
 		}
 		break;
 	case 'p':		/* PasswordMessage */
+		/* too early */
+		if (!client->auth_user) {
+			disconnect_client(client, true, "client password pkt before startup packet");
+			return false;
+		}
+
 		/* haven't requested it */
 		if (cf_auth_type <= AUTH_TRUST) {
 			disconnect_client(client, true, "unrequested passwd pkt");
```
