# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in c
**Pair ID:** 1025_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1025_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```c
Lines 138-178 of the vulnerable file.


static int daemon_msg_stats_req(uint8 ver, struct daemon_slpars *pars,
    struct session *session, uint32 plen, struct pcap_stat *stats,
    unsigned int svrcapt);

static int daemon_msg_setsampling_req(uint8 ver, struct daemon_slpars *pars,
    uint32 plen, struct rpcap_sampling *samp_param);

static void daemon_seraddr(struct sockaddr_storage *sockaddrin, struct rpcap_sockaddr *sockaddrout);
#ifdef _WIN32
static unsigned __stdcall daemon_thrdatamain(void *ptr);
#else
static void *daemon_thrdatamain(void *ptr);
static void noop_handler(int sign);
#endif

static int rpcapd_recv_msg_header(SOCKET sock, struct rpcap_header *headerp);
static int rpcapd_recv(SOCKET sock, char *buffer, size_t toread, uint32 *plen, char *errmsgbuf);
static int rpcapd_discard(SOCKET sock, uint32 len);
static void session_close(struct session *);

int
daemon_serviceloop(SOCKET sockctrl, int isactive, char *passiveClients,
    int nullAuthAllowed)
{
	struct daemon_slpars pars;		// service loop parameters
	char errbuf[PCAP_ERRBUF_SIZE + 1];	// keeps the error string, prior to be printed
	char errmsgbuf[PCAP_ERRBUF_SIZE + 1];	// buffer for errors to send to the client
	int host_port_check_status;
	int nrecv;
	struct rpcap_header header;		// RPCAP message general header
	uint32 plen;				// payload length from header
	int authenticated = 0;			// 1 if the client has successfully authenticated
	char source[PCAP_BUF_SIZE+1];		// keeps the string that contains the interface to open
	int got_source = 0;			// 1 if we've gotten the source from an open request
#ifndef _WIN32
	struct sigaction action;
#endif
	struct session *session = NULL;		// struct session main variable
	const char *msg_type_string;		// string for message type
	int client_told_us_to_close = 0;	// 1 if the client told us to close the capture
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,6 +155,8 @@
 static int rpcapd_recv(SOCKET sock, char *buffer, size_t toread, uint32 *plen, char *errmsgbuf);
 static int rpcapd_discard(SOCKET sock, uint32 len);
 static void session_close(struct session *);
+
+static int is_url(const char *source);
 
 int
 daemon_serviceloop(SOCKET sockctrl, int isactive, char *passiveClients,
@@ -1554,8 +1556,13 @@
 	source[nread] = '\0';
 	plen -= nread;
 
-	// XXX - make sure it's *not* a URL; we don't support opening
-	// remote devices here.
+	// Is this a URL rather than a device?
+	// If so, reject it.
+	if (is_url(source))
+	{
+		pcap_snprintf(errmsgbuf, PCAP_ERRBUF_SIZE, "Source string refers to a remote device");
+		goto error;
+	}
 
 	// Open the selected device
 	// This is a fake open, since we do that only to get the needed parameters, then we close the device again
@@ -2647,3 +2654,66 @@
 		session->fp = NULL;
 	}
 }
+
+// Check whether a capture source string is a URL or not.
+// This includes URLs that refer to a local device; a scheme, followed
+// by ://, followed by *another* scheme and ://, is just silly, and
+// anybody who supplies that will get an error.
+//
+static int
+is_url(const char *source)
+{
+	char *colonp;
+
+	/*
+	 * RFC 3986 says:
+	 *
+	 *   URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
+	 *
+	 *   hier-part   = "//" authority path-abempty
+	 *               / path-absolute
+	 *               / path-rootless
+	 *               / path-empty
+	 *
+	 *   authority   = [ userinfo "@" ] host [ ":" port ]
+	 *
+	 *   userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
+	 *
+	 * Step 1: look for the ":" at the end of the scheme.
+	 * A colon in the source is *NOT* sufficient to indicate that
+	 * this is a URL, as interface names on some platforms might
+	 * include colons (e.g., I think some Solaris interfaces
+	 * might).
+	 */
+	colonp = strchr(source, ':');
+	if (colonp == NULL)
+	{
+		/*
+		 * The source is the device to open.  It's not a URL.
+		 */
+		return (0);
+	}
+
+	/*
+	 * All schemes must have "//" after them, i.e. we only support
+	 * hier-part   = "//" authority path-abempty, not
+	 * hier-part   = path-absolute
+	 * hier-part   = path-rootless
+	 * hier-part   = path-empty
+	 *
+	 * We need that in order to distinguish between a local device
+	 * name that happens to contain a colon and a URI.
+	 */
+	if (strncmp(colonp + 1, "//", 2) != 0)
+	{
+		/*
+		 * The source is the device to open.  It's not a URL.
+		 */
+		return (0);
+	}
+
+	/*
+	 * It's a URL.
+	 */
+	return (1);
+}
```
