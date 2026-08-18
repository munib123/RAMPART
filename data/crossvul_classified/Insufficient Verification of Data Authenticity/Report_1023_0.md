# CrossVul Fix Pair: Insufficient Verification of Data Authenticity in c
**Pair ID:** 1023_0
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-345
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1023_0`)

## Vulnerability Information & PoC

## Description
Insufficient Verification of Data Authenticity - The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Vulnerable Code
```c
Lines 1159-1199 of the vulnerable file.

{
#ifdef _WIN32
	/*
	 * Warning: the user which launches the process must have the
	 * SE_TCB_NAME right.
	 * This corresponds to have the "Act as part of the Operating System"
	 * turned on (administrative tools, local security settings, local
	 * policies, user right assignment)
	 * However, it seems to me that if you run it as a service, this
	 * right should be provided by default.
	 *
	 * XXX - hopefully, this returns errors such as ERROR_LOGON_FAILURE,
	 * which merely indicates that the user name or password is
	 * incorrect, not whether it's the user name or the password
	 * that's incorrect, so a client that's trying to brute-force
	 * accounts doesn't know whether it's the user name or the
	 * password that's incorrect, so it doesn't know whether to
	 * stop trying to log in with a given user name and move on
	 * to another user name.
	 */
	HANDLE Token;
	if (LogonUser(username, ".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &Token) == 0)
	{
		pcap_fmt_errmsg_for_win32_err(errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "LogonUser() failed");
		return -1;
	}

	// This call should change the current thread to the selected user.
	// I didn't test it.
	if (ImpersonateLoggedOnUser(Token) == 0)
	{
		pcap_fmt_errmsg_for_win32_err(errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "ImpersonateLoggedOnUser() failed");
		CloseHandle(Token);
		return -1;
	}

	CloseHandle(Token);
	return 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1176,11 +1176,22 @@
 	 * stop trying to log in with a given user name and move on
 	 * to another user name.
 	 */
+	DWORD error;
 	HANDLE Token;
+	char errmsgbuf[PCAP_ERRBUF_SIZE];	// buffer for errors to log
+
 	if (LogonUser(username, ".", password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &Token) == 0)
 	{
-		pcap_fmt_errmsg_for_win32_err(errbuf, PCAP_ERRBUF_SIZE,
-		    GetLastError(), "LogonUser() failed");
+		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed");
+		error = GetLastError();
+		if (error != ERROR_LOGON_FAILURE)
+		{
+			// Some error other than an authentication error;
+			// log it.
+			pcap_fmt_errmsg_for_win32_err(errmsgbuf,
+			    PCAP_ERRBUF_SIZE, error, "LogonUser() failed");
+			rpcapd_log(LOGPRIO_ERROR, "%s", errmsgbuf);
+		}			    
 		return -1;
 	}
 
@@ -1188,8 +1199,10 @@
 	// I didn't test it.
 	if (ImpersonateLoggedOnUser(Token) == 0)
 	{
-		pcap_fmt_errmsg_for_win32_err(errbuf, PCAP_ERRBUF_SIZE,
+		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed");
+		pcap_fmt_errmsg_for_win32_err(errmsgbuf, PCAP_ERRBUF_SIZE,
 		    GetLastError(), "ImpersonateLoggedOnUser() failed");
+		rpcapd_log(LOGPRIO_ERROR, "%s", errmsgbuf);
 		CloseHandle(Token);
 		return -1;
 	}
@@ -1217,6 +1230,7 @@
 	 * only password database or some other authentication mechanism,
 	 * behind its API.
 	 */
+	int error;
 	struct passwd *user;
 	char *user_password;
 #ifdef HAVE_GETSPNAM
@@ -1227,7 +1241,7 @@
 	// This call is needed to get the uid
 	if ((user = getpwnam(username)) == NULL)
 	{
-		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
+		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed");
 		return -1;
 	}
 
@@ -1235,7 +1249,7 @@
 	// This call is needed to get the password; otherwise 'x' is returned
 	if ((usersp = getspnam(username)) == NULL)
 	{
-		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
+		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed");
 		return -1;
 	}
 	user_password = usersp->sp_pwdp;
@@ -1253,29 +1267,52 @@
 	user_password = user->pw_passwd;
 #endif
 
+	//
+	// The Single UNIX Specification says that if crypt() fails it
+	// sets errno, but some implementatons that haven't been run
+	// through the SUS test suite might not do so.
+	//
+	errno = 0;
 	crypt_password = crypt(password, user_password);
 	if (crypt_password == NULL)
 	{
+		error = errno;
 		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed");
+		if (error == 0)
+		{
+			// It didn't set errno.
+			rpcapd_log(LOGPRIO_ERROR, "crypt() failed");
+		}
+		else
+		{
+			rpcapd_log(LOGPRIO_ERROR, "crypt() failed: %s",
+			    strerror(error));
+		}
 		return -1;
 	}
 	if (strcmp(user_password, crypt_password) != 0)
 	{
-		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed: user name or password incorrect");
+		pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE, "Authentication failed");
 		return -1;
 	}
 
 	if (setuid(user->pw_uid))
 	{
+		error = errno;
 		pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
-		    errno, "setuid");
+		    error, "setuid");
+		rpcapd_log(LOGPRIO_ERROR, "setuid() failed: %s",
+		    strerror(error));
 		return -1;
 	}
 
 /*	if (setgid(user->pw_gid))
 	{
+		error = errno;
 		pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
 		    errno, "setgid");
+		rpcapd_log(LOGPRIO_ERROR, "setgid() failed: %s",
+		    strerror(error));
 		return -1;
 	}
 */
```
