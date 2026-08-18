# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5752_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5752_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 670-710 of the vulnerable file.


		err = -EACCES;
		if (ipcperms(ns, &msq->q_perm, S_IWUGO))
			goto out_unlock_free;

		err = security_msg_queue_msgsnd(msq, msg, msgflg);
		if (err)
			goto out_unlock_free;

		if (msgsz + msq->q_cbytes <= msq->q_qbytes &&
				1 + msq->q_qnum <= msq->q_qbytes) {
			break;
		}

		/* queue full, wait: */
		if (msgflg & IPC_NOWAIT) {
			err = -EAGAIN;
			goto out_unlock_free;
		}
		ss_add(msq, &s);
		ipc_rcu_getref(msq);
		msg_unlock(msq);
		schedule();

		ipc_lock_by_ptr(&msq->q_perm);
		ipc_rcu_putref(msq);
		if (msq->q_perm.deleted) {
			err = -EIDRM;
			goto out_unlock_free;
		}
		ss_del(&s);

		if (signal_pending(current)) {
			err = -ERESTARTNOHAND;
			goto out_unlock_free;
		}
	}

	msq->q_lspid = task_tgid_vnr(current);
	msq->q_stime = get_seconds();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -687,7 +687,12 @@
 			goto out_unlock_free;
 		}
 		ss_add(msq, &s);
-		ipc_rcu_getref(msq);
+
+		if (!ipc_rcu_getref(msq)) {
+			err = -EIDRM;
+			goto out_unlock_free;
+		}
+
 		msg_unlock(msq);
 		schedule();
 
```
