# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 264_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `264_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 677-717 of the vulnerable file.


static void
rx_cache_insert(netdissect_options *ndo,
                const u_char *bp, const struct ip *ip, int dport)
{
	struct rx_cache_entry *rxent;
	const struct rx_header *rxh = (const struct rx_header *) bp;

	if (ndo->ndo_snapend - bp + 1 <= (int)(sizeof(struct rx_header) + sizeof(int32_t)))
		return;

	rxent = &rx_cache[rx_cache_next];

	if (++rx_cache_next >= RX_CACHE_SIZE)
		rx_cache_next = 0;

	rxent->callnum = EXTRACT_32BITS(&rxh->callNumber);
	UNALIGNED_MEMCPY(&rxent->client, &ip->ip_src, sizeof(uint32_t));
	UNALIGNED_MEMCPY(&rxent->server, &ip->ip_dst, sizeof(uint32_t));
	rxent->dport = dport;
	rxent->serviceId = EXTRACT_32BITS(&rxh->serviceId);
	rxent->opcode = EXTRACT_32BITS(bp + sizeof(struct rx_header));
}

/*
 * Lookup an entry in the cache.  Also taken from print-nfs.c
 *
 * Note that because this is a reply, we're looking at the _source_
 * port.
 */

static int
rx_cache_find(const struct rx_header *rxh, const struct ip *ip, int sport,
	      int32_t *opcode)
{
	int i;
	struct rx_cache_entry *rxent;
	uint32_t clip;
	uint32_t sip;

	UNALIGNED_MEMCPY(&clip, &ip->ip_dst, sizeof(uint32_t));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -694,7 +694,7 @@
 	UNALIGNED_MEMCPY(&rxent->client, &ip->ip_src, sizeof(uint32_t));
 	UNALIGNED_MEMCPY(&rxent->server, &ip->ip_dst, sizeof(uint32_t));
 	rxent->dport = dport;
-	rxent->serviceId = EXTRACT_32BITS(&rxh->serviceId);
+	rxent->serviceId = EXTRACT_16BITS(&rxh->serviceId);
 	rxent->opcode = EXTRACT_32BITS(bp + sizeof(struct rx_header));
 }
 
@@ -725,7 +725,7 @@
 		if (rxent->callnum == EXTRACT_32BITS(&rxh->callNumber) &&
 		    rxent->client.s_addr == clip &&
 		    rxent->server.s_addr == sip &&
-		    rxent->serviceId == EXTRACT_32BITS(&rxh->serviceId) &&
+		    rxent->serviceId == EXTRACT_16BITS(&rxh->serviceId) &&
 		    rxent->dport == sport) {
 
 			/* We got a match! */
```
