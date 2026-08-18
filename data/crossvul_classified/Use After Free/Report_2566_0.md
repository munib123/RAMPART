# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2566_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2566_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1253-1293 of the vulnerable file.


			/* TODO: add a header? */
			skb_put(nc, NOTIFY_COOKIE_LEN);
			/* and attach it to the socket */
retry:
			f = fdget(notification->sigev_signo);
			if (!f.file) {
				ret = -EBADF;
				goto out;
			}
			sock = netlink_getsockbyfilp(f.file);
			fdput(f);
			if (IS_ERR(sock)) {
				ret = PTR_ERR(sock);
				sock = NULL;
				goto out;
			}

			timeo = MAX_SCHEDULE_TIMEOUT;
			ret = netlink_attachskb(sock, nc, &timeo, NULL);
			if (ret == 1)
				goto retry;
			if (ret) {
				sock = NULL;
				nc = NULL;
				goto out;
			}
		}
	}

	f = fdget(mqdes);
	if (!f.file) {
		ret = -EBADF;
		goto out;
	}

	inode = file_inode(f.file);
	if (unlikely(f.file->f_op != &mqueue_file_operations)) {
		ret = -EBADF;
		goto out_fput;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1270,8 +1270,10 @@
 
 			timeo = MAX_SCHEDULE_TIMEOUT;
 			ret = netlink_attachskb(sock, nc, &timeo, NULL);
-			if (ret == 1)
+			if (ret == 1) {
+				sock = NULL;
 				goto retry;
+			}
 			if (ret) {
 				sock = NULL;
 				nc = NULL;
```
