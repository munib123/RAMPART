# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1718_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1718_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1067-1107 of the vulnerable file.


	if (!options.use_pam)
		fatal("UsePAM not set, but ended up in %s anyway", __func__);

	ret = do_pam_account();

	buffer_put_int(m, ret);
	buffer_put_string(m, buffer_ptr(&loginmsg), buffer_len(&loginmsg));

	mm_request_send(sock, MONITOR_ANS_PAM_ACCOUNT, m);

	return (ret);
}

static void *sshpam_ctxt, *sshpam_authok;
extern KbdintDevice sshpam_device;

int
mm_answer_pam_init_ctx(int sock, Buffer *m)
{

	debug3("%s", __func__);
	authctxt->user = buffer_get_string(m, NULL);
	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
	sshpam_authok = NULL;
	buffer_clear(m);
	if (sshpam_ctxt != NULL) {
		monitor_permit(mon_dispatch, MONITOR_REQ_PAM_FREE_CTX, 1);
		buffer_put_int(m, 1);
	} else {
		buffer_put_int(m, 0);
	}
	mm_request_send(sock, MONITOR_ANS_PAM_INIT_CTX, m);
	return (0);
}

int
mm_answer_pam_query(int sock, Buffer *m)
{
	char *name = NULL, *info = NULL, **prompts = NULL;
	u_int i, num = 0, *echo_on = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1084,9 +1084,7 @@
 int
 mm_answer_pam_init_ctx(int sock, Buffer *m)
 {
-
 	debug3("%s", __func__);
-	authctxt->user = buffer_get_string(m, NULL);
 	sshpam_ctxt = (sshpam_device.init_ctx)(authctxt);
 	sshpam_authok = NULL;
 	buffer_clear(m);
```
