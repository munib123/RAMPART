# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3351_2
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3351_2`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 59-99 of the vulnerable file.

				nn->nfs_callback_tcpport6, PF_INET6, net);
	} else if (ret != -EAFNOSUPPORT)
		goto out_err;
	return 0;

out_err:
	return (ret) ? ret : -ENOMEM;
}

/*
 * This is the NFSv4 callback kernel thread.
 */
static int
nfs4_callback_svc(void *vrqstp)
{
	int err;
	struct svc_rqst *rqstp = vrqstp;

	set_freezable();

	while (!kthread_should_stop()) {
		/*
		 * Listen for a request on the socket
		 */
		err = svc_recv(rqstp, MAX_SCHEDULE_TIMEOUT);
		if (err == -EAGAIN || err == -EINTR)
			continue;
		svc_process(rqstp);
	}
	return 0;
}

#if defined(CONFIG_NFS_V4_1)
/*
 * The callback service for NFSv4.1 callbacks
 */
static int
nfs41_callback_svc(void *vrqstp)
{
	struct svc_rqst *rqstp = vrqstp;
	struct svc_serv *serv = rqstp->rq_server;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,7 +76,10 @@
 
 	set_freezable();
 
-	while (!kthread_should_stop()) {
+	while (!kthread_freezable_should_stop(NULL)) {
+
+		if (signal_pending(current))
+			flush_signals(current);
 		/*
 		 * Listen for a request on the socket
 		 */
@@ -85,6 +88,8 @@
 			continue;
 		svc_process(rqstp);
 	}
+	svc_exit_thread(rqstp);
+	module_put_and_exit(0);
 	return 0;
 }
 
@@ -103,9 +108,10 @@
 
 	set_freezable();
 
-	while (!kthread_should_stop()) {
-		if (try_to_freeze())
-			continue;
+	while (!kthread_freezable_should_stop(NULL)) {
+
+		if (signal_pending(current))
+			flush_signals(current);
 
 		prepare_to_wait(&serv->sv_cb_waitq, &wq, TASK_INTERRUPTIBLE);
 		spin_lock_bh(&serv->sv_cb_lock);
@@ -121,11 +127,13 @@
 				error);
 		} else {
 			spin_unlock_bh(&serv->sv_cb_lock);
-			schedule();
+			if (!kthread_should_stop())
+				schedule();
 			finish_wait(&serv->sv_cb_waitq, &wq);
 		}
-		flush_signals(current);
-	}
+	}
+	svc_exit_thread(rqstp);
+	module_put_and_exit(0);
 	return 0;
 }
 
@@ -221,14 +229,14 @@
 static struct svc_serv_ops nfs40_cb_sv_ops = {
 	.svo_function		= nfs4_callback_svc,
 	.svo_enqueue_xprt	= svc_xprt_do_enqueue,
-	.svo_setup		= svc_set_num_threads,
+	.svo_setup		= svc_set_num_threads_sync,
 	.svo_module		= THIS_MODULE,
 };
 #if defined(CONFIG_NFS_V4_1)
 static struct svc_serv_ops nfs41_cb_sv_ops = {
 	.svo_function		= nfs41_callback_svc,
 	.svo_enqueue_xprt	= svc_xprt_do_enqueue,
-	.svo_setup		= svc_set_num_threads,
+	.svo_setup		= svc_set_num_threads_sync,
 	.svo_module		= THIS_MODULE,
 };
 
@@ -280,7 +288,7 @@
 		printk(KERN_WARNING "nfs_callback_create_svc: no kthread, %d users??\n",
 			cb_info->users);
 
-	serv = svc_create(&nfs4_callback_program, NFS4_CALLBACK_BUFSIZE, sv_ops);
+	serv = svc_create_pooled(&nfs4_callback_program, NFS4_CALLBACK_BUFSIZE, sv_ops);
 	if (!serv) {
 		printk(KERN_ERR "nfs_callback_create_svc: create service failed\n");
 		return ERR_PTR(-ENOMEM);
```
