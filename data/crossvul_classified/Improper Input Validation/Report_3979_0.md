# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3979_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3979_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: scp.c,v 1.208 2020/04/30 17:07:10 markus Exp $ */
/*
 * scp - secure remote copy.  This is basically patched BSD rcp which
 * uses ssh to do the data transfer (instead of using rcmd).
 *
 * NOTE: This version should NOT be suid root.  (This uses ssh to
 * do the transfer and ssh has the necessary privileges.)
 *
 * 1995 Timo Rinne <tri@iki.fi>, Tatu Ylonen <ylo@cs.hut.fi>
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1999 Aaron Campbell.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: scp.c,v 1.208 2020/04/30 17:07:10 markus Exp $ */
+/* $OpenBSD: scp.c,v 1.209 2020/05/01 06:31:42 djm Exp $ */
 /*
  * scp - secure remote copy.  This is basically patched BSD rcp which
  * uses ssh to do the data transfer (instead of using rcmd).
@@ -374,6 +374,7 @@
 void lostconn(int);
 int okname(char *);
 void run_err(const char *,...);
+int note_err(const char *,...);
 void verifydir(char *);
 
 struct passwd *pwd;
@@ -1231,9 +1232,6 @@
 {
 	static BUF buffer;
 	struct stat stb;
-	enum {
-		YES, NO, DISPLAYED
-	} wrerr;
 	BUF *bp;
 	off_t i;
 	size_t j, count;
@@ -1241,7 +1239,7 @@
 	mode_t mode, omode, mask;
 	off_t size, statbytes;
 	unsigned long long ull;
-	int setimes, targisdir, wrerrno = 0;
+	int setimes, targisdir, wrerr;
 	char ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
 	char **patterns = NULL;
 	size_t n, npatterns = 0;
@@ -1450,8 +1448,13 @@
 			continue;
 		}
 		cp = bp->buf;
-		wrerr = NO;
-
+		wrerr = 0;
+
+		/*
+		 * NB. do not use run_err() unless immediately followed by
+		 * exit() below as it may send a spurious reply that might
+		 * desyncronise us from the peer. Use note_err() instead.
+		 */
 		statbytes = 0;
 		if (showprogress)
 			start_progress_meter(curfile, size, &statbytes);
@@ -1476,11 +1479,12 @@
 
 			if (count == bp->cnt) {
 				/* Keep reading so we stay sync'd up. */
-				if (wrerr == NO) {
+				if (!wrerr) {
 					if (atomicio(vwrite, ofd, bp->buf,
 					    count) != count) {
-						wrerr = YES;
-						wrerrno = errno;
+						note_err("%s: %s", np,
+						    strerror(errno));
+						wrerr = 1;
 					}
 				}
 				count = 0;
@@ -1488,16 +1492,14 @@
 			}
 		}
 		unset_nonblock(remin);
-		if (count != 0 && wrerr == NO &&
+		if (count != 0 && !wrerr &&
 		    atomicio(vwrite, ofd, bp->buf, count) != count) {
-			wrerr = YES;
-			wrerrno = errno;
-		}
-		if (wrerr == NO && (!exists || S_ISREG(stb.st_mode)) &&
-		    ftruncate(ofd, size) != 0) {
-			run_err("%s: truncate: %s", np, strerror(errno));
-			wrerr = DISPLAYED;
-		}
+			note_err("%s: %s", np, strerror(errno));
+			wrerr = 1;
+		}
+		if (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
+		    ftruncate(ofd, size) != 0)
+			note_err("%s: truncate: %s", np, strerror(errno));
 		if (pflag) {
 			if (exists || omode != mode)
 #ifdef HAVE_FCHMOD
@@ -1505,9 +1507,8 @@
 #else /* HAVE_FCHMOD */
 				if (chmod(np, omode)) {
 #endif /* HAVE_FCHMOD */
-					run_err("%s: set mode: %s",
+					note_err("%s: set mode: %s",
 					    np, strerror(errno));
-					wrerr = DISPLAYED;
 				}
 		} else {
 			if (!exists && omode != mode)
@@ -1516,36 +1517,25 @@
 #else /* HAVE_FCHMOD */
 				if (chmod(np, omode & ~mask)) {
 #endif /* HAVE_FCHMOD */
-					run_err("%s: set mode: %s",
+					note_err("%s: set mode: %s",
 					    np, strerror(errno));
-					wrerr = DISPLAYED;
 				}
 		}
-		if (close(ofd) == -1) {
-			wrerr = YES;
-			wrerrno = errno;
-		}
+		if (close(ofd) == -1)
+			note_err(np, "%s: close: %s", np, strerror(errno));
 		(void) response();
 		if (showprogress)
 			stop_progress_meter();
-		if (setimes && wrerr == NO) {
+		if (setimes && !wrerr) {
 			setimes = 0;
 			if (utimes(np, tv) == -1) {
-				run_err("%s: set times: %s",
+				note_err("%s: set times: %s",
 				    np, strerror(errno));
-				wrerr = DISPLAYED;
-			}
-		}
-		switch (wrerr) {
-		case YES:
-			run_err("%s: %s", np, strerror(wrerrno));
-			break;
-		case NO:
+			}
+		}
+		/* If no error was noted then signal success for this file */
+		if (note_err(NULL) == 0)
 			(void) atomicio(vwrite, remout, "", 1);
-			break;
-		case DISPLAYED:
-			break;
-		}
 	}
 done:
 	for (n = 0; n < npatterns; n++)
@@ -1631,6 +1621,38 @@
 		va_end(ap);
 		fprintf(stderr, "\n");
 	}
+}
+
+/*
+ * Notes a sink error for sending at the end of a file transfer. Returns 0 if
+ * no error has been noted or -1 otherwise. Use note_err(NULL) to flush
+ * any active error at the end of the transfer.
+ */
+int
+note_err(const char *fmt, ...)
+{
+	static char *emsg;
+	va_list ap;
+
+	/* Replay any previously-noted error */
+	if (fmt == NULL) {
+		if (emsg == NULL)
+			return 0;
+		run_err("%s", emsg);
+		free(emsg);
+		emsg = NULL;
+		return -1;
+	}
+
+	errs++;
+	/* Prefer first-noted error */
+	if (emsg != NULL)
+		return -1;
+
+	va_start(ap, fmt);
+	vasnmprintf(&emsg, INT_MAX, NULL, fmt, ap);
+	va_end(ap);
+	return -1;
 }
 
 void
```
