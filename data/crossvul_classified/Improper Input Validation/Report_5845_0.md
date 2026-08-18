# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5845_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5845_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 144-185 of the vulnerable file.

unlock:
	release_sock(sk);

	return err ?: size;
}

static int hash_recvmsg(struct kiocb *unused, struct socket *sock,
			struct msghdr *msg, size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct hash_ctx *ctx = ask->private;
	unsigned ds = crypto_ahash_digestsize(crypto_ahash_reqtfm(&ctx->req));
	int err;

	if (len > ds)
		len = ds;
	else if (len < ds)
		msg->msg_flags |= MSG_TRUNC;

	msg->msg_namelen = 0;

	lock_sock(sk);
	if (ctx->more) {
		ctx->more = 0;
		ahash_request_set_crypt(&ctx->req, NULL, ctx->result, 0);
		err = af_alg_wait_for_completion(crypto_ahash_final(&ctx->req),
						 &ctx->completion);
		if (err)
			goto unlock;
	}

	err = memcpy_toiovec(msg->msg_iov, ctx->result, len);

unlock:
	release_sock(sk);

	return err ?: len;
}

static int hash_accept(struct socket *sock, struct socket *newsock, int flags)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -161,8 +161,6 @@
 	else if (len < ds)
 		msg->msg_flags |= MSG_TRUNC;
 
-	msg->msg_namelen = 0;
-
 	lock_sock(sk);
 	if (ctx->more) {
 		ctx->more = 0;
```
