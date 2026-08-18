# CrossVul Fix Pair: Authentication Bypass by Spoofing in c
**Pair ID:** 3010_0
**Vulnerability Class:** Authentication Bypass
**CWE:** CWE-290
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3010_0`)

## Vulnerability Information & PoC

## Description
Authentication Bypass by Spoofing - This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Vulnerable Code
```c
Lines 3873-3915 of the vulnerable file.

  {
    *ptr++ = '\0';
    con->clientport = atoi(ptr);
  }
  else
    con->clientport = con->serverport;

 /*
  * Then validate...
  */

  if (httpAddrLocalhost(httpGetAddress(con->http)))
  {
   /*
    * Only allow "localhost" or the equivalent IPv4 or IPv6 numerical
    * addresses when accessing CUPS via the loopback interface...
    */

    return (!_cups_strcasecmp(con->clientname, "localhost") ||
	    !_cups_strcasecmp(con->clientname, "localhost.") ||
#ifdef __linux
	    !_cups_strcasecmp(con->clientname, "localhost.localdomain") ||
#endif /* __linux */
            !strcmp(con->clientname, "127.0.0.1") ||
	    !strcmp(con->clientname, "[::1]"));
  }

#if defined(HAVE_DNSSD) || defined(HAVE_AVAHI)
 /*
  * Check if the hostname is something.local (Bonjour); if so, allow it.
  */

  if ((end = strrchr(con->clientname, '.')) != NULL && end > con->clientname &&
      !end[1])
  {
   /*
    * "." on end, work back to second-to-last "."...
    */

    for (end --; end > con->clientname && *end != '.'; end --);
  }

  if (end && (!_cups_strcasecmp(end, ".local") ||
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3890,9 +3890,6 @@
 
     return (!_cups_strcasecmp(con->clientname, "localhost") ||
 	    !_cups_strcasecmp(con->clientname, "localhost.") ||
-#ifdef __linux
-	    !_cups_strcasecmp(con->clientname, "localhost.localdomain") ||
-#endif /* __linux */
             !strcmp(con->clientname, "127.0.0.1") ||
 	    !strcmp(con->clientname, "[::1]"));
   }
```
