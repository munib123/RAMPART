# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1719_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1719_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1149-1189 of the vulnerable file.

		ret = (sshpam_device.respond)(sshpam_ctxt, num, resp);
		for (i = 0; i < num; ++i)
			free(resp[i]);
		free(resp);
	} else {
		ret = (sshpam_device.respond)(sshpam_ctxt, num, NULL);
	}
	buffer_clear(m);
	buffer_put_int(m, ret);
	mm_request_send(sock, MONITOR_ANS_PAM_RESPOND, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	if (ret == 0)
		sshpam_authok = sshpam_ctxt;
	return (0);
}

int
mm_answer_pam_free_ctx(int sock, Buffer *m)
{

	debug3("%s", __func__);
	(sshpam_device.free_ctx)(sshpam_ctxt);
	buffer_clear(m);
	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
	auth_method = "keyboard-interactive";
	auth_submethod = "pam";
	return (sshpam_authok == sshpam_ctxt);
}
#endif

int
mm_answer_keyallowed(int sock, Buffer *m)
{
	Key *key;
	char *cuser, *chost;
	u_char *blob;
	u_int bloblen, pubkey_auth_attempt;
	enum mm_keytype type = 0;
	int allowed = 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1166,14 +1166,16 @@
 int
 mm_answer_pam_free_ctx(int sock, Buffer *m)
 {
+	int r = sshpam_authok != NULL && sshpam_authok == sshpam_ctxt;
 
 	debug3("%s", __func__);
 	(sshpam_device.free_ctx)(sshpam_ctxt);
+	sshpam_ctxt = sshpam_authok = NULL;
 	buffer_clear(m);
 	mm_request_send(sock, MONITOR_ANS_PAM_FREE_CTX, m);
 	auth_method = "keyboard-interactive";
 	auth_submethod = "pam";
-	return (sshpam_authok == sshpam_ctxt);
+	return r;
 }
 #endif
 
```
