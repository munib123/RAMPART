# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5715_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5715_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 255-295 of the vulnerable file.

	else
		return peer_recv_fastpath_pdu(client, s);
}

static int peer_recv_callback(rdpTransport* transport, wStream* s, void* extra)
{
	freerdp_peer* client = (freerdp_peer*) extra;
	rdpRdp* rdp = client->context->rdp;

	switch (rdp->state)
	{
		case CONNECTION_STATE_INITIAL:
			if (!rdp_server_accept_nego(rdp, s))
				return -1;

			if (rdp->nego->selected_protocol & PROTOCOL_NLA)
			{
				sspi_CopyAuthIdentity(&client->identity, &(rdp->nego->transport->credssp->identity));
				IFCALLRET(client->Logon, client->authenticated, client, &client->identity, TRUE);
				credssp_free(rdp->nego->transport->credssp);
			}
			else
			{
				IFCALLRET(client->Logon, client->authenticated, client, &client->identity, FALSE);
			}

			break;

		case CONNECTION_STATE_NEGO:
			if (!rdp_server_accept_mcs_connect_initial(rdp, s))
				return -1;
			break;

		case CONNECTION_STATE_MCS_CONNECT:
			if (!rdp_server_accept_mcs_erect_domain_request(rdp, s))
				return -1;
			break;

		case CONNECTION_STATE_MCS_ERECT_DOMAIN:
			if (!rdp_server_accept_mcs_attach_user_request(rdp, s))
				return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -272,6 +272,7 @@
 				sspi_CopyAuthIdentity(&client->identity, &(rdp->nego->transport->credssp->identity));
 				IFCALLRET(client->Logon, client->authenticated, client, &client->identity, TRUE);
 				credssp_free(rdp->nego->transport->credssp);
+				rdp->nego->transport->credssp = NULL;
 			}
 			else
 			{
```
