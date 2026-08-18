# CrossVul Fix Pair: Missing Authorization in c
**Pair ID:** 4459_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4459_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 303-343 of the vulnerable file.

		X_UNLOCK;
		return 0;
	}

	xim = XShmCreateImage_wr(dpy, default_visual, depth, ZPixmap, NULL,
	    shm, w, h);

	if (xim == NULL) {
		rfbErr("XShmCreateImage(%s) failed.\n", name);
		if (quiet) {
			fprintf(stderr, "XShmCreateImage(%s) failed.\n", name);
		}
		X_UNLOCK;
		return 0;
	}

	*ximg_ptr = xim;

#if HAVE_XSHM
	shm->shmid = shmget(IPC_PRIVATE,
	    xim->bytes_per_line * xim->height, IPC_CREAT | 0777);

	if (shm->shmid == -1) {
		rfbErr("shmget(%s) failed.\n", name);
		rfbLogPerror("shmget");

		XDestroyImage(xim);
		*ximg_ptr = NULL;

		X_UNLOCK;
		return 0;
	}

	shm->shmaddr = xim->data = (char *) shmat(shm->shmid, 0, 0);

	if (shm->shmaddr == (char *)-1) {
		rfbErr("shmat(%s) failed.\n", name);
		rfbLogPerror("shmat");

		XDestroyImage(xim);
		*ximg_ptr = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -320,7 +320,7 @@
 
 #if HAVE_XSHM
 	shm->shmid = shmget(IPC_PRIVATE,
-	    xim->bytes_per_line * xim->height, IPC_CREAT | 0777);
+	    xim->bytes_per_line * xim->height, IPC_CREAT | 0600);
 
 	if (shm->shmid == -1) {
 		rfbErr("shmget(%s) failed.\n", name);
```
