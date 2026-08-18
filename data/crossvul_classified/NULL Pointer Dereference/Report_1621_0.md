# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1621_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1621_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 21-61 of the vulnerable file.

 */

#include "bouncer.h"

#include <usual/pgutil.h>

static const char *hdr2hex(const struct MBuf *data, char *buf, unsigned buflen)
{
	const uint8_t *bin = data->data + data->read_pos;
	unsigned int dlen;

	dlen = mbuf_avail_for_read(data);
	return bin2hex(bin, dlen, buf, buflen);
}

static bool check_client_passwd(PgSocket *client, const char *passwd)
{
	char md5[MD5_PASSWD_LEN + 1];
	const char *correct;
	PgUser *user = client->auth_user;

	/* disallow empty passwords */
	if (!*passwd || !*user->passwd)
		return false;

	switch (cf_auth_type) {
	case AUTH_PLAIN:
		return strcmp(user->passwd, passwd) == 0;
	case AUTH_CRYPT:
		correct = crypt(user->passwd, (char *)client->tmp_login_salt);
		return correct && strcmp(correct, passwd) == 0;
	case AUTH_MD5:
		if (strlen(passwd) != MD5_PASSWD_LEN)
			return false;
		if (!isMD5(user->passwd))
			pg_md5_encrypt(user->passwd, user->name, strlen(user->name), user->passwd);
		pg_md5_encrypt(user->passwd + 3, (char *)client->tmp_login_salt, 4, md5);
		return strcmp(md5, passwd) == 0;
	}
	return false;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,12 @@
 	const char *correct;
 	PgUser *user = client->auth_user;
 
+	/* auth_user may be missing */
+	if (!user) {
+		slog_error(client, "Password packet before auth packet?");
+		return false;
+	}
+
 	/* disallow empty passwords */
 	if (!*passwd || !*user->passwd)
 		return false;
```
