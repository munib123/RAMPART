# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1024_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1024_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1205-1245 of the vulnerable file.

	 *
	 * We use the Solaris/Linux shadow password authentication if
	 * we have getspnam(), otherwise we just do traditional
	 * authentication, which, on some platforms, might work, even
	 * with shadow passwords, if we're running as root.  Traditional
	 * authenticaion won't work if we're not running as root, as
	 * I think these days all UN*Xes either won't return the password
	 * at all with getpwnam() or will only do so if you're root.
	 *
	 * XXX - perhaps what we *should* be using is PAM, if we have
	 * it.  That might hide all the details of username/password
	 * authentication, whether it's done with a visible-to-root-
	 * only password database or some other authentication mechanism,
	 * behind its API.
	 */
	struct passwd *user;
	char *user_password;
#ifdef HAVE_GETSPNAM
	struct spwd *usersp;
#endif

	// This call is needed to get the uid
	if ((user = getpwnam(username)) == NULL)
	{
		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
		return -1;
	}

#ifdef HAVE_GETSPNAM
	// This call is needed to get the password; otherwise 'x' is returned
	if ((usersp = getspnam(username)) == NULL)
	{
		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
		return -1;
	}
	user_password = usersp->sp_pwdp;
#else
	/*
	 * XXX - what about other platforms?
	 * The unixpapa.com page claims this Just Works on *BSD if you're
	 * running as root - it's from 2000, so it doesn't indicate whether
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1222,6 +1222,7 @@
 #ifdef HAVE_GETSPNAM
 	struct spwd *usersp;
 #endif
+	char *crypt_password;
 
 	// This call is needed to get the uid
 	if ((user = getpwnam(username)) == NULL)
@@ -1252,7 +1253,13 @@
 	user_password = user->pw_passwd;
 #endif
 
-	if (strcmp(user_password, (char *) crypt(password, user_password)) != 0)
+	crypt_password = crypt(password, user_password);
+	if (crypt_password == NULL)
+	{
+		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed");
+		return -1;
+	}
+	if (strcmp(user_password, crypt_password) != 0)
 	{
 		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
 		return -1;
```
