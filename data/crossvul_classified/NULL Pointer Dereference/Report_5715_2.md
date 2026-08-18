# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5715_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5715_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 142-182 of the vulnerable file.

	/* Network Level Authentication */

	if (transport->settings->Authentication != TRUE)
		return TRUE;

	settings = transport->settings;
	instance = (freerdp*) settings->instance;

	if (transport->credssp == NULL)
		transport->credssp = credssp_new(instance, transport, settings);

	if (credssp_authenticate(transport->credssp) < 0)
	{
		if (!connectErrorCode)
			connectErrorCode = AUTHENTICATIONERROR;

		fprintf(stderr, "Authentication failure, check credentials.\n"
			"If credentials are valid, the NTLMSSP implementation may be to blame.\n");

		credssp_free(transport->credssp);
		return FALSE;
	}

	credssp_free(transport->credssp);

	return TRUE;
}

BOOL transport_tsg_connect(rdpTransport* transport, const char* hostname, UINT16 port)
{
	rdpTsg* tsg = tsg_new(transport);

	tsg->transport = transport;
	transport->tsg = tsg;
	transport->SplitInputOutput = TRUE;

	if (transport->TlsIn == NULL)
		transport->TlsIn = tls_new(transport->settings);

	transport->TlsIn->sockfd = transport->TcpIn->sockfd;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -159,6 +159,7 @@
 			"If credentials are valid, the NTLMSSP implementation may be to blame.\n");
 
 		credssp_free(transport->credssp);
+		transport->credssp = NULL;
 		return FALSE;
 	}
 
@@ -292,6 +293,7 @@
 	{
 		fprintf(stderr, "client authentication failure\n");
 		credssp_free(transport->credssp);
+		transport->credssp = NULL;
 		return FALSE;
 	}
 
```
