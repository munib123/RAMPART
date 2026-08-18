# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3290_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3290_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 730-770 of the vulnerable file.

	/* Release the thread */
	svc_exit_thread(rqstp);

	nfsd_destroy(net);

	/* Release module */
	mutex_unlock(&nfsd_mutex);
	module_put_and_exit(0);
	return 0;
}

static __be32 map_new_errors(u32 vers, __be32 nfserr)
{
	if (nfserr == nfserr_jukebox && vers == 2)
		return nfserr_dropit;
	if (nfserr == nfserr_wrongsec && vers < 4)
		return nfserr_acces;
	return nfserr;
}

int
nfsd_dispatch(struct svc_rqst *rqstp, __be32 *statp)
{
	struct svc_procedure	*proc;
	kxdrproc_t		xdr;
	__be32			nfserr;
	__be32			*nfserrp;

	dprintk("nfsd_dispatch: vers %d proc %d\n",
				rqstp->rq_vers, rqstp->rq_proc);
	proc = rqstp->rq_procinfo;

	/*
	 * Give the xdr decoder a chance to change this if it wants
	 * (necessary in the NFSv4.0 compound case)
	 */
	rqstp->rq_cachetype = proc->pc_cachetype;
	/* Decode arguments */
	xdr = proc->pc_decode;
	if (xdr && !xdr(rqstp, (__be32*)rqstp->rq_arg.head[0].iov_base,
			rqstp->rq_argp)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -747,6 +747,37 @@
 	return nfserr;
 }
 
+/*
+ * A write procedure can have a large argument, and a read procedure can
+ * have a large reply, but no NFSv2 or NFSv3 procedure has argument and
+ * reply that can both be larger than a page.  The xdr code has taken
+ * advantage of this assumption to be a sloppy about bounds checking in
+ * some cases.  Pending a rewrite of the NFSv2/v3 xdr code to fix that
+ * problem, we enforce these assumptions here:
+ */
+static bool nfs_request_too_big(struct svc_rqst *rqstp,
+				struct svc_procedure *proc)
+{
+	/*
+	 * The ACL code has more careful bounds-checking and is not
+	 * susceptible to this problem:
+	 */
+	if (rqstp->rq_prog != NFS_PROGRAM)
+		return false;
+	/*
+	 * Ditto NFSv4 (which can in theory have argument and reply both
+	 * more than a page):
+	 */
+	if (rqstp->rq_vers >= 4)
+		return false;
+	/* The reply will be small, we're OK: */
+	if (proc->pc_xdrressize > 0 &&
+	    proc->pc_xdrressize < XDR_QUADLEN(PAGE_SIZE))
+		return false;
+
+	return rqstp->rq_arg.len > PAGE_SIZE;
+}
+
 int
 nfsd_dispatch(struct svc_rqst *rqstp, __be32 *statp)
 {
@@ -759,6 +790,11 @@
 				rqstp->rq_vers, rqstp->rq_proc);
 	proc = rqstp->rq_procinfo;
 
+	if (nfs_request_too_big(rqstp, proc)) {
+		dprintk("nfsd: NFSv%d argument too large\n", rqstp->rq_vers);
+		*statp = rpc_garbage_args;
+		return 1;
+	}
 	/*
 	 * Give the xdr decoder a chance to change this if it wants
 	 * (necessary in the NFSv4.0 compound case)
```
