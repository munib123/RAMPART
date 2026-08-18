# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 3626_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3626_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 20-60 of the vulnerable file.

longer anything like firedns, there are many major
differences between this code and the original.
Please do not assume that firedns works like this,
looks like this, walks like this or tastes like this.
*/

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include "inspircd_win32wrapper.h"
#endif

#include "inspircd.h"
#include "socketengine.h"
#include "configreader.h"
#include "socket.h"

/** Masks to mask off the responses we get from the DNSRequest methods
 */
enum QueryInfo
{
	ERROR_MASK	= 0x10000	/* Result is an error */
};

/** Flags which can be ORed into a request or reply for different meanings
 */
enum QueryFlags
{
	FLAGS_MASK_RD		= 0x01,	/* Recursive */
	FLAGS_MASK_TC		= 0x02,
	FLAGS_MASK_AA		= 0x04,	/* Authoritative */
	FLAGS_MASK_OPCODE	= 0x78,
	FLAGS_MASK_QR		= 0x80,
	FLAGS_MASK_RCODE	= 0x0F,	/* Request */
	FLAGS_MASK_Z		= 0x70,
	FLAGS_MASK_RA 		= 0x80
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,8 @@
 #include "configreader.h"
 #include "socket.h"
 
+#define DN_COMP_BITMASK	0xC000		/* highest 6 bits in a DN label header */
+
 /** Masks to mask off the responses we get from the DNSRequest methods
  */
 enum QueryInfo
@@ -98,7 +100,7 @@
 
 	DNSRequest(DNS* dns, int id, const std::string &original);
 	~DNSRequest();
-	DNSInfo ResultIsReady(DNSHeader &h, int length);
+	DNSInfo ResultIsReady(DNSHeader &h, unsigned length);
 	int SendRequests(const DNSHeader *header, const int length, QueryType qt);
 };
 
@@ -161,7 +163,10 @@
 /* Allocate the processing buffer */
 DNSRequest::DNSRequest(DNS* dns, int rid, const std::string &original) : dnsobj(dns)
 {
-	res = new unsigned char[512];
+	/* hardening against overflow here:  make our work buffer twice the theoretical
+	 * maximum size so that hostile input doesn't screw us over.
+	 */
+	res = new unsigned char[sizeof(DNSHeader) * 2];
 	*res = 0;
 	orig = original;
 	RequestTimeout* RT = new RequestTimeout(ServerInstance->Config->dns_timeout ? ServerInstance->Config->dns_timeout : 5, this, rid);
@@ -688,11 +693,11 @@
 }
 
 /** A result is ready, process it */
-DNSInfo DNSRequest::ResultIsReady(DNSHeader &header, int length)
-{
-	int i = 0;
+DNSInfo DNSRequest::ResultIsReady(DNSHeader &header, unsigned length)
+{
+	unsigned i = 0, o;
 	int q = 0;
-	int curanswer, o;
+	int curanswer;
 	ResourceRecord rr;
  	unsigned short ptr;
 
@@ -790,17 +795,31 @@
 
 	switch (rr.type)
 	{
+		/*
+		 * CNAME and PTR are compressed.  We need to decompress them.
+		 */
 		case DNS_QUERY_CNAME:
-			/* CNAME and PTR have the same processing code */
 		case DNS_QUERY_PTR:
 			o = 0;
 			q = 0;
 			while (q == 0 && i < length && o + 256 < 1023)
 			{
+				/* DN label found (byte over 63) */
 				if (header.payload[i] > 63)
 				{
 					memcpy(&ptr,&header.payload[i],2);
-					i = ntohs(ptr) - 0xC000 - 12;
+
+					i = ntohs(ptr);
+
+					/* check that highest two bits are set. if not, we've been had */
+					if (!(i & DN_COMP_BITMASK))
+						return std::make_pair((unsigned char *) NULL, "DN label decompression header is bogus");
+
+					/* mask away the two highest bits. */
+					i &= ~DN_COMP_BITMASK;
+
+					/* and decrease length by 12 bytes. */
+					i =- 12;
 				}
 				else
 				{
@@ -813,7 +832,11 @@
 						res[o] = 0;
 						if (o != 0)
 							res[o++] = '.';
-						memcpy(&res[o],&header.payload[i + 1],header.payload[i]);
+
+						if (o + header.payload[i] > sizeof(DNSHeader))
+							return std::make_pair((unsigned char *) NULL, "DN label decompression is impossible -- malformed/hostile packet?");
+
+						memcpy(&res[o], &header.payload[i + 1], header.payload[i]);
 						o += header.payload[i];
 						i += header.payload[i] + 1;
 					}
@@ -822,16 +845,21 @@
 			res[o] = 0;
 		break;
 		case DNS_QUERY_AAAA:
+			if (rr.rdlength != sizeof(struct in6_addr))
+				return std::make_pair((unsigned char *) NULL, "rr.rdlength is larger than 16 bytes for an ipv6 entry -- malformed/hostile packet?");
+
 			memcpy(res,&header.payload[i],rr.rdlength);
 			res[rr.rdlength] = 0;
 		break;
 		case DNS_QUERY_A:
+			if (rr.rdlength != sizeof(struct in_addr))
+				return std::make_pair((unsigned char *) NULL, "rr.rdlength is larger than 4 bytes for an ipv4 entry -- malformed/hostile packet?");
+
 			memcpy(res,&header.payload[i],rr.rdlength);
 			res[rr.rdlength] = 0;
 		break;
 		default:
-			memcpy(res,&header.payload[i],rr.rdlength);
-			res[rr.rdlength] = 0;
+			return std::make_pair((unsigned char *) NULL, "don't know how to handle undefined type (" + ConvToStr(rr.type) + ") -- rejecting");
 		break;
 	}
 	return std::make_pair(res,"No error");
```
