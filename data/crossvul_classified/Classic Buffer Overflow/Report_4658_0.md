# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4658_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4658_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 1403-1443 of the vulnerable file.

		/* Return because we're waiting for something real. */
		return;

	case EAPT_MD5CHAP:
		if (len < 1) {
			error("EAP: received MD5-Challenge with no data");
			/* Bogus request; wait for something real. */
			return;
		}
		GETCHAR(vallen, inp);
		len--;
		if (vallen < 8 || vallen > len) {
			error("EAP: MD5-Challenge with bad length %d (8..%d)",
			    vallen, len);
			/* Try something better. */
			eap_send_nak(esp, id, EAPT_SRP);
			break;
		}

		/* Not so likely to happen. */
		if (vallen >= len + sizeof (rhostname)) {
			dbglog("EAP: trimming really long peer name down");
			BCOPY(inp + vallen, rhostname, sizeof (rhostname) - 1);
			rhostname[sizeof (rhostname) - 1] = '\0';
		} else {
			BCOPY(inp + vallen, rhostname, len - vallen);
			rhostname[len - vallen] = '\0';
		}

		/* In case the remote doesn't give us his name. */
		if (explicit_remote ||
		    (remote_name[0] != '\0' && vallen == len))
			strlcpy(rhostname, remote_name, sizeof (rhostname));

		/*
		 * Get the secret for authenticating ourselves with
		 * the specified host.
		 */
		if (!get_secret(esp->es_unit, esp->es_client.ea_name,
		    rhostname, secret, &secret_len, 0)) {
			dbglog("EAP: no MD5 secret for auth to %q", rhostname);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1420,7 +1420,7 @@
 		}
 
 		/* Not so likely to happen. */
-		if (vallen >= len + sizeof (rhostname)) {
+		if (len - vallen >= sizeof (rhostname)) {
 			dbglog("EAP: trimming really long peer name down");
 			BCOPY(inp + vallen, rhostname, sizeof (rhostname) - 1);
 			rhostname[sizeof (rhostname) - 1] = '\0';
@@ -1846,7 +1846,7 @@
 		}
 
 		/* Not so likely to happen. */
-		if (vallen >= len + sizeof (rhostname)) {
+		if (len - vallen >= sizeof (rhostname)) {
 			dbglog("EAP: trimming really long peer name down");
 			BCOPY(inp + vallen, rhostname, sizeof (rhostname) - 1);
 			rhostname[sizeof (rhostname) - 1] = '\0';
```
