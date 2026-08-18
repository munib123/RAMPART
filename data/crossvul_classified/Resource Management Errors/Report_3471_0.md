# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3471_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3471_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 691-731 of the vulnerable file.


	if (resp->status != nlm_lck_denied_nolocks)
		printk("lockd: unexpected unlock status: %d\n", resp->status);
	/* What to do now? I'm out of my depth... */
	status = -ENOLCK;
out:
	nlmclnt_release_call(req);
	return status;
}

static void nlmclnt_unlock_callback(struct rpc_task *task, void *data)
{
	struct nlm_rqst	*req = data;
	u32 status = ntohl(req->a_res.status);

	if (RPC_ASSASSINATED(task))
		goto die;

	if (task->tk_status < 0) {
		dprintk("lockd: unlock failed (err = %d)\n", -task->tk_status);
		goto retry_rebind;
	}
	if (status == NLM_LCK_DENIED_GRACE_PERIOD) {
		rpc_delay(task, NLMCLNT_GRACE_WAIT);
		goto retry_unlock;
	}
	if (status != NLM_LCK_GRANTED)
		printk(KERN_WARNING "lockd: unexpected unlock status: %d\n", status);
die:
	return;
 retry_rebind:
	nlm_rebind_host(req->a_host);
 retry_unlock:
	rpc_restart_call(task);
}

static const struct rpc_call_ops nlmclnt_unlock_ops = {
	.rpc_call_done = nlmclnt_unlock_callback,
	.rpc_release = nlmclnt_rpc_release,
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -708,7 +708,13 @@
 
 	if (task->tk_status < 0) {
 		dprintk("lockd: unlock failed (err = %d)\n", -task->tk_status);
-		goto retry_rebind;
+		switch (task->tk_status) {
+		case -EACCES:
+		case -EIO:
+			goto die;
+		default:
+			goto retry_rebind;
+		}
 	}
 	if (status == NLM_LCK_DENIED_GRACE_PERIOD) {
 		rpc_delay(task, NLMCLNT_GRACE_WAIT);
```
