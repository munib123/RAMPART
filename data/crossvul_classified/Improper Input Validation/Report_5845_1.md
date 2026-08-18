# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5845_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5845_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 415-455 of the vulnerable file.

	return err ?: size;
}

static int skcipher_recvmsg(struct kiocb *unused, struct socket *sock,
			    struct msghdr *msg, size_t ignored, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct skcipher_ctx *ctx = ask->private;
	unsigned bs = crypto_ablkcipher_blocksize(crypto_ablkcipher_reqtfm(
		&ctx->req));
	struct skcipher_sg_list *sgl;
	struct scatterlist *sg;
	unsigned long iovlen;
	struct iovec *iov;
	int err = -EAGAIN;
	int used;
	long copied = 0;

	lock_sock(sk);
	msg->msg_namelen = 0;
	for (iov = msg->msg_iov, iovlen = msg->msg_iovlen; iovlen > 0;
	     iovlen--, iov++) {
		unsigned long seglen = iov->iov_len;
		char __user *from = iov->iov_base;

		while (seglen) {
			sgl = list_first_entry(&ctx->tsgl,
					       struct skcipher_sg_list, list);
			sg = sgl->sg;

			while (!sg->length)
				sg++;

			used = ctx->used;
			if (!used) {
				err = skcipher_wait_for_data(sk, flags);
				if (err)
					goto unlock;
			}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -432,7 +432,6 @@
 	long copied = 0;
 
 	lock_sock(sk);
-	msg->msg_namelen = 0;
 	for (iov = msg->msg_iov, iovlen = msg->msg_iovlen; iovlen > 0;
 	     iovlen--, iov++) {
 		unsigned long seglen = iov->iov_len;
```
