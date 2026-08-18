# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3351_1
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3351_1`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 853-901 of the vulnerable file.


static const struct rpc_call_ops nlmsvc_grant_ops = {
	.rpc_call_done = nlmsvc_grant_callback,
	.rpc_release = nlmsvc_grant_release,
};

/*
 * We received a GRANT_RES callback. Try to find the corresponding
 * block.
 */
void
nlmsvc_grant_reply(struct nlm_cookie *cookie, __be32 status)
{
	struct nlm_block	*block;

	dprintk("grant_reply: looking for cookie %x, s=%d \n",
		*(unsigned int *)(cookie->data), status);
	if (!(block = nlmsvc_find_block(cookie)))
		return;

	if (block) {
		if (status == nlm_lck_denied_grace_period) {
			/* Try again in a couple of seconds */
			nlmsvc_insert_block(block, 10 * HZ);
		} else {
			/* Lock is now held by client, or has been rejected.
			 * In both cases, the block should be removed. */
			nlmsvc_unlink_block(block);
		}
	}
	nlmsvc_release_block(block);
}

/* Helper function to handle retry of a deferred block.
 * If it is a blocking lock, call grant_blocked.
 * For a non-blocking lock or test lock, revisit the request.
 */
static void
retry_deferred_block(struct nlm_block *block)
{
	if (!(block->b_flags & B_GOT_CALLBACK))
		block->b_flags |= B_TIMED_OUT;
	nlmsvc_insert_block(block, NLM_TIMEOUT);
	dprintk("revisit block %p flags %d\n",	block, block->b_flags);
	if (block->b_deferred_req) {
		block->b_deferred_req->revisit(block->b_deferred_req, 0);
		block->b_deferred_req = NULL;
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -870,15 +870,15 @@
 	if (!(block = nlmsvc_find_block(cookie)))
 		return;
 
-	if (block) {
-		if (status == nlm_lck_denied_grace_period) {
-			/* Try again in a couple of seconds */
-			nlmsvc_insert_block(block, 10 * HZ);
-		} else {
-			/* Lock is now held by client, or has been rejected.
-			 * In both cases, the block should be removed. */
-			nlmsvc_unlink_block(block);
-		}
+	if (status == nlm_lck_denied_grace_period) {
+		/* Try again in a couple of seconds */
+		nlmsvc_insert_block(block, 10 * HZ);
+	} else {
+		/*
+		 * Lock is now held by client, or has been rejected.
+		 * In both cases, the block should be removed.
+		 */
+		nlmsvc_unlink_block(block);
 	}
 	nlmsvc_release_block(block);
 }
```
