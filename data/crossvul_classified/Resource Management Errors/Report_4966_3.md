# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4966_3
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4966_3`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1479-1519 of the vulnerable file.

	} else {
		struct unix_address *addr = u->addr;

		*uaddr_len = addr->len;
		memcpy(sunaddr, addr->name, *uaddr_len);
	}
	unix_state_unlock(sk);
	sock_put(sk);
out:
	return err;
}

static void unix_detach_fds(struct scm_cookie *scm, struct sk_buff *skb)
{
	int i;

	scm->fp = UNIXCB(skb).fp;
	UNIXCB(skb).fp = NULL;

	for (i = scm->fp->count-1; i >= 0; i--)
		unix_notinflight(scm->fp->fp[i]);
}

static void unix_destruct_scm(struct sk_buff *skb)
{
	struct scm_cookie scm;
	memset(&scm, 0, sizeof(scm));
	scm.pid  = UNIXCB(skb).pid;
	if (UNIXCB(skb).fp)
		unix_detach_fds(&scm, skb);

	/* Alas, it calls VFS */
	/* So fscking what? fput() had been SMP-safe since the last Summer */
	scm_destroy(&scm);
	sock_wfree(skb);
}

/*
 * The "user->unix_inflight" variable is protected by the garbage
 * collection lock, and we just read it locklessly here. If you go
 * over the limit, there might be a tiny race in actually noticing
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1496,7 +1496,7 @@
 	UNIXCB(skb).fp = NULL;
 
 	for (i = scm->fp->count-1; i >= 0; i--)
-		unix_notinflight(scm->fp->fp[i]);
+		unix_notinflight(scm->fp->user, scm->fp->fp[i]);
 }
 
 static void unix_destruct_scm(struct sk_buff *skb)
@@ -1561,7 +1561,7 @@
 		return -ENOMEM;
 
 	for (i = scm->fp->count - 1; i >= 0; i--)
-		unix_inflight(scm->fp->fp[i]);
+		unix_inflight(scm->fp->user, scm->fp->fp[i]);
 	return max_level;
 }
 
```
