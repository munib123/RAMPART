# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2171_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2171_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1651-1691 of the vulnerable file.

		if (ack->subh.addip_hdr->serial ==
				htonl(asoc->peer.addip_serial))
			break;

		list_del_init(&ack->transmitted_list);
		sctp_chunk_free(ack);
	}
}

/* Find the ASCONF_ACK whose serial number matches ASCONF */
struct sctp_chunk *sctp_assoc_lookup_asconf_ack(
					const struct sctp_association *asoc,
					__be32 serial)
{
	struct sctp_chunk *ack;

	/* Walk through the list of cached ASCONF-ACKs and find the
	 * ack chunk whose serial number matches that of the request.
	 */
	list_for_each_entry(ack, &asoc->asconf_ack_list, transmitted_list) {
		if (ack->subh.addip_hdr->serial == serial) {
			sctp_chunk_hold(ack);
			return ack;
		}
	}

	return NULL;
}

void sctp_asconf_queue_teardown(struct sctp_association *asoc)
{
	/* Free any cached ASCONF_ACK chunk. */
	sctp_assoc_free_asconf_acks(asoc);

	/* Free the ASCONF queue. */
	sctp_assoc_free_asconf_queue(asoc);

	/* Free any cached ASCONF chunk. */
	if (asoc->addip_last_asconf)
		sctp_chunk_free(asoc->addip_last_asconf);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1668,6 +1668,8 @@
 	 * ack chunk whose serial number matches that of the request.
 	 */
 	list_for_each_entry(ack, &asoc->asconf_ack_list, transmitted_list) {
+		if (sctp_chunk_pending(ack))
+			continue;
 		if (ack->subh.addip_hdr->serial == serial) {
 			sctp_chunk_hold(ack);
 			return ack;
```
