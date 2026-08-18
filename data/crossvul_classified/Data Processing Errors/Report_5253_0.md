# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 5253_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5253_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 2227-2267 of the vulnerable file.


		if (timeout) {
			ktime_get_ts(timeout);
			*timeout = timespec_sub(end_time, *timeout);
			if (timeout->tv_sec < 0) {
				timeout->tv_sec = timeout->tv_nsec = 0;
				break;
			}

			/* Timeout, return less than vlen datagrams */
			if (timeout->tv_nsec == 0 && timeout->tv_sec == 0)
				break;
		}

		/* Out of band data, return right away */
		if (msg_sys.msg_flags & MSG_OOB)
			break;
		cond_resched();
	}

out_put:
	fput_light(sock->file, fput_needed);

	if (err == 0)
		return datagrams;

	if (datagrams != 0) {
		/*
		 * We may return less entries than requested (vlen) if the
		 * sock is non block and there aren't enough datagrams...
		 */
		if (err != -EAGAIN) {
			/*
			 * ... or  if recvmsg returns an error after we
			 * received some datagrams, where we record the
			 * error to return on the next call or if the
			 * app asks about it using getsockopt(SO_ERROR).
			 */
			sock->sk->sk_err = -err;
		}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2244,31 +2244,31 @@
 		cond_resched();
 	}
 
+	if (err == 0)
+		goto out_put;
+
+	if (datagrams == 0) {
+		datagrams = err;
+		goto out_put;
+	}
+
+	/*
+	 * We may return less entries than requested (vlen) if the
+	 * sock is non block and there aren't enough datagrams...
+	 */
+	if (err != -EAGAIN) {
+		/*
+		 * ... or  if recvmsg returns an error after we
+		 * received some datagrams, where we record the
+		 * error to return on the next call or if the
+		 * app asks about it using getsockopt(SO_ERROR).
+		 */
+		sock->sk->sk_err = -err;
+	}
 out_put:
 	fput_light(sock->file, fput_needed);
 
-	if (err == 0)
-		return datagrams;
-
-	if (datagrams != 0) {
-		/*
-		 * We may return less entries than requested (vlen) if the
-		 * sock is non block and there aren't enough datagrams...
-		 */
-		if (err != -EAGAIN) {
-			/*
-			 * ... or  if recvmsg returns an error after we
-			 * received some datagrams, where we record the
-			 * error to return on the next call or if the
-			 * app asks about it using getsockopt(SO_ERROR).
-			 */
-			sock->sk->sk_err = -err;
-		}
-
-		return datagrams;
-	}
-
-	return err;
+	return datagrams;
 }
 
 SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
```
