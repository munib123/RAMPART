# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5714_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5714_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 700-740 of the vulnerable file.

			printf("FATAL: cannot decrypt\n");
			return FALSE; /* TODO */
		}

		if (!security_fips_check_signature(s->p, length - pad, sig, rdp))
		{
			printf("FATAL: invalid packet signature\n");
			return FALSE; /* TODO */
		}

		/* is this what needs adjusting? */
		s->size -= pad;
		return TRUE;
	}

	if (stream_get_left(s) < 8)
		return FALSE;

	stream_read(s, wmac, sizeof(wmac));
	length -= sizeof(wmac);
	security_decrypt(s->p, length, rdp);

	if (securityFlags & SEC_SECURE_CHECKSUM)
		security_salted_mac_signature(rdp, s->p, length, FALSE, cmac);
	else
		security_mac_signature(rdp, s->p, length, cmac);

	if (memcmp(wmac, cmac, sizeof(wmac)) != 0)
	{
		printf("WARNING: invalid packet signature\n");
		/*
		 * Because Standard RDP Security is totally broken,
		 * and cannot protect against MITM, don't treat signature
		 * verification failure as critical. This at least enables
		 * us to work with broken RDP clients and servers that
		 * generate invalid signatures.
		 */
		//return FALSE;
	}

	return TRUE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -717,7 +717,8 @@
 
 	stream_read(s, wmac, sizeof(wmac));
 	length -= sizeof(wmac);
-	security_decrypt(s->p, length, rdp);
+	if (!security_decrypt(s->p, length, rdp))
+		return FALSE;
 
 	if (securityFlags & SEC_SECURE_CHECKSUM)
 		security_salted_mac_signature(rdp, s->p, length, FALSE, cmac);
```
