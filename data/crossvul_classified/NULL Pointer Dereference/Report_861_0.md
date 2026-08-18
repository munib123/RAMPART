# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 861_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `861_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1833-1873 of the vulnerable file.

	int bodylen;
	struct NameValueParserData data;
	char * int_ip, * int_port, * rem_host, * rem_port, * protocol;
	int opt=0;
	/*int proto=0;*/
	unsigned short iport, rport;

	if (GETFLAG(IPV6FCFWDISABLEDMASK))
	{
		SoapError(h, 702, "FirewallDisabled");
		return;
	}

	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	int_ip = GetValueFromNameValueList(&data, "InternalClient");
	int_port = GetValueFromNameValueList(&data, "InternalPort");
	rem_host = GetValueFromNameValueList(&data, "RemoteHost");
	rem_port = GetValueFromNameValueList(&data, "RemotePort");
	protocol = GetValueFromNameValueList(&data, "Protocol");

	rport = (unsigned short)atoi(rem_port);
	iport = (unsigned short)atoi(int_port);
	/*proto = atoi(protocol);*/

	syslog(LOG_INFO, "%s: retrieving timeout for outbound pinhole from [%s]:%hu to [%s]:%hu protocol %s", action, int_ip, iport,rem_host, rport, protocol);

	/* TODO */
	r = -1;/*upnp_check_outbound_pinhole(proto, &opt);*/

	switch(r)
	{
		case 1:	/* success */
			bodylen = snprintf(body, sizeof(body), resp,
			                   action, ns/*"urn:schemas-upnp-org:service:WANIPv6FirewallControl:1"*/,
			                   opt, action);
			BuildSendAndCloseSoapResp(h, body, bodylen);
			break;
		case -5:	/* Protocol not supported */
			SoapError(h, 705, "ProtocolNotSupported");
			break;
		default:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1850,6 +1850,13 @@
 	rem_port = GetValueFromNameValueList(&data, "RemotePort");
 	protocol = GetValueFromNameValueList(&data, "Protocol");
 
+	if (!int_port || !ext_port || !protocol)
+	{
+		ClearNameValueList(&data);
+		SoapError(h, 402, "Invalid Args");
+		return;
+	}
+
 	rport = (unsigned short)atoi(rem_port);
 	iport = (unsigned short)atoi(int_port);
 	/*proto = atoi(protocol);*/
```
