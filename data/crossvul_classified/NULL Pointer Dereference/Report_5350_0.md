# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5350_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5350_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 164-204 of the vulnerable file.

	}

	err = memcpy_to_msg(msg, ctx->result, len);

unlock:
	release_sock(sk);

	return err ?: len;
}

static int hash_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct hash_ctx *ctx = ask->private;
	struct ahash_request *req = &ctx->req;
	char state[crypto_ahash_statesize(crypto_ahash_reqtfm(req))];
	struct sock *sk2;
	struct alg_sock *ask2;
	struct hash_ctx *ctx2;
	int err;

	err = crypto_ahash_export(req, state);
	if (err)
		return err;

	err = af_alg_accept(ask->parent, newsock);
	if (err)
		return err;

	sk2 = newsock->sk;
	ask2 = alg_sk(sk2);
	ctx2 = ask2->private;
	ctx2->more = 1;

	err = crypto_ahash_import(&ctx2->req, state);
	if (err) {
		sock_orphan(sk2);
		sock_put(sk2);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,9 +181,14 @@
 	struct sock *sk2;
 	struct alg_sock *ask2;
 	struct hash_ctx *ctx2;
+	bool more;
 	int err;
 
-	err = crypto_ahash_export(req, state);
+	lock_sock(sk);
+	more = ctx->more;
+	err = more ? crypto_ahash_export(req, state) : 0;
+	release_sock(sk);
+
 	if (err)
 		return err;
 
@@ -194,7 +199,10 @@
 	sk2 = newsock->sk;
 	ask2 = alg_sk(sk2);
 	ctx2 = ask2->private;
-	ctx2->more = 1;
+	ctx2->more = more;
+
+	if (!more)
+		return err;
 
 	err = crypto_ahash_import(&ctx2->req, state);
 	if (err) {
```
