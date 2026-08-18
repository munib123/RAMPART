# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2172_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2172_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 153-193 of the vulnerable file.

static sctp_disposition_t __sctp_sf_do_9_1_abort(struct net *net,
					const struct sctp_endpoint *ep,
					const struct sctp_association *asoc,
					const sctp_subtype_t type,
					void *arg,
					sctp_cmd_seq_t *commands);

/* Small helper function that checks if the chunk length
 * is of the appropriate length.  The 'required_length' argument
 * is set to be the size of a specific chunk we are testing.
 * Return Values:  1 = Valid length
 * 		   0 = Invalid length
 *
 */
static inline int
sctp_chunk_length_valid(struct sctp_chunk *chunk,
			   __u16 required_length)
{
	__u16 chunk_length = ntohs(chunk->chunk_hdr->length);

	if (unlikely(chunk_length < required_length))
		return 0;

	return 1;
}

/**********************************************************
 * These are the state functions for handling chunk events.
 **********************************************************/

/*
 * Process the final SHUTDOWN COMPLETE.
 *
 * Section: 4 (C) (diagram), 9.2
 * Upon reception of the SHUTDOWN COMPLETE chunk the endpoint will verify
 * that it is in SHUTDOWN-ACK-SENT state, if it is not the chunk should be
 * discarded. If the endpoint is in the SHUTDOWN-ACK-SENT state the endpoint
 * should stop the T2-shutdown timer and remove all knowledge of the
 * association (and thus the association enters the CLOSED state).
 *
 * Verification Tag: 8.5.1(C), sctpimpguide 2.41.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -170,6 +170,9 @@
 {
 	__u16 chunk_length = ntohs(chunk->chunk_hdr->length);
 
+	/* Previously already marked? */
+	if (unlikely(chunk->pdiscard))
+		return 0;
 	if (unlikely(chunk_length < required_length))
 		return 0;
 
```
