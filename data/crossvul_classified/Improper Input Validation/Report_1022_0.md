# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1022_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1022_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1318-1358 of the vulnerable file.

		return -1;
	}
*/
	return 0;

#endif

}

static int
daemon_msg_findallif_req(uint8 ver, struct daemon_slpars *pars, uint32 plen)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// buffer for network errors
	char errmsgbuf[PCAP_ERRBUF_SIZE];	// buffer for errors to send to the client
	char sendbuf[RPCAP_NETBUF_SIZE];	// temporary buffer in which data to be sent is buffered
	int sendbufidx = 0;			// index which keeps the number of bytes currently buffered
	pcap_if_t *alldevs = NULL;		// pointer to the header of the interface chain
	pcap_if_t *d;				// temp pointer needed to scan the interface chain
	struct pcap_addr *address;		// pcap structure that keeps a network address of an interface
	struct rpcap_findalldevs_if *findalldevs_if;// rpcap structure that packet all the data of an interface together
	uint16 nif = 0;				// counts the number of interface listed

	// Discard the rest of the message; there shouldn't be any payload.
	if (rpcapd_discard(pars->sockctrl, plen) == -1)
	{
		// Network error.
		return -1;
	}

	// Retrieve the device list
	if (pcap_findalldevs(&alldevs, errmsgbuf) == -1)
		goto error;

	if (alldevs == NULL)
	{
		if (rpcap_senderror(pars->sockctrl, ver, PCAP_ERR_NOREMOTEIF,
			"No interfaces found! Make sure libpcap/WinPcap is properly installed"
			" and you have the right to access to the remote device.",
			errbuf) == -1)
		{
			rpcapd_log(LOGPRIO_ERROR, "Send to client failed: %s", errbuf);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1335,6 +1335,7 @@
 	pcap_if_t *d;				// temp pointer needed to scan the interface chain
 	struct pcap_addr *address;		// pcap structure that keeps a network address of an interface
 	struct rpcap_findalldevs_if *findalldevs_if;// rpcap structure that packet all the data of an interface together
+	uint32 replylen;			// length of reply payload
 	uint16 nif = 0;				// counts the number of interface listed
 
 	// Discard the rest of the message; there shouldn't be any payload.
@@ -1361,17 +1362,19 @@
 		return 0;
 	}
 
-	// checks the number of interfaces and it computes the total length of the payload
+	// This checks the number of interfaces and computes the total
+	// length of the payload.
+	replylen = 0;
 	for (d = alldevs; d != NULL; d = d->next)
 	{
 		nif++;
 
 		if (d->description)
-			plen+= strlen(d->description);
+			replylen += strlen(d->description);
 		if (d->name)
-			plen+= strlen(d->name);
-
-		plen+= sizeof(struct rpcap_findalldevs_if);
+			replylen += strlen(d->name);
+
+		replylen += sizeof(struct rpcap_findalldevs_if);
 
 		for (address = d->addresses; address != NULL; address = address->next)
 		{
@@ -1384,7 +1387,7 @@
 #ifdef AF_INET6
 			case AF_INET6:
 #endif
-				plen+= (sizeof(struct rpcap_sockaddr) * 4);
+				replylen += (sizeof(struct rpcap_sockaddr) * 4);
 				break;
 
 			default:
@@ -1400,7 +1403,7 @@
 		goto error;
 
 	rpcap_createhdr((struct rpcap_header *) sendbuf, ver,
-	    RPCAP_MSG_FINDALLIF_REPLY, nif, plen);
+	    RPCAP_MSG_FINDALLIF_REPLY, nif, replylen);
 
 	// send the interface list
 	for (d = alldevs; d != NULL; d = d->next)
```
