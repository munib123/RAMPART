# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5483_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5483_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 3405-3445 of the vulnerable file.

				void *arg,
				sctp_cmd_seq_t *commands)
{
	struct sctp_chunk *chunk = arg;
	struct sk_buff *skb = chunk->skb;
	sctp_chunkhdr_t *ch;
	sctp_errhdr_t *err;
	__u8 *ch_end;
	int ootb_shut_ack = 0;
	int ootb_cookie_ack = 0;

	SCTP_INC_STATS(net, SCTP_MIB_OUTOFBLUES);

	ch = (sctp_chunkhdr_t *) chunk->chunk_hdr;
	do {
		/* Report violation if the chunk is less then minimal */
		if (ntohs(ch->length) < sizeof(sctp_chunkhdr_t))
			return sctp_sf_violation_chunklen(net, ep, asoc, type, arg,
						  commands);

		/* Now that we know we at least have a chunk header,
		 * do things that are type appropriate.
		 */
		if (SCTP_CID_SHUTDOWN_ACK == ch->type)
			ootb_shut_ack = 1;

		/* RFC 2960, Section 3.3.7
		 *   Moreover, under any circumstances, an endpoint that
		 *   receives an ABORT  MUST NOT respond to that ABORT by
		 *   sending an ABORT of its own.
		 */
		if (SCTP_CID_ABORT == ch->type)
			return sctp_sf_pdiscard(net, ep, asoc, type, arg, commands);

		/* RFC 8.4, 7) If the packet contains a "Stale cookie" ERROR
		 * or a COOKIE ACK the SCTP Packet should be silently
		 * discarded.
		 */

		if (SCTP_CID_COOKIE_ACK == ch->type)
			ootb_cookie_ack = 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3422,6 +3422,12 @@
 			return sctp_sf_violation_chunklen(net, ep, asoc, type, arg,
 						  commands);
 
+		/* Report violation if chunk len overflows */
+		ch_end = ((__u8 *)ch) + SCTP_PAD4(ntohs(ch->length));
+		if (ch_end > skb_tail_pointer(skb))
+			return sctp_sf_violation_chunklen(net, ep, asoc, type, arg,
+						  commands);
+
 		/* Now that we know we at least have a chunk header,
 		 * do things that are type appropriate.
 		 */
@@ -3452,12 +3458,6 @@
 				}
 			}
 		}
-
-		/* Report violation if chunk len overflows */
-		ch_end = ((__u8 *)ch) + SCTP_PAD4(ntohs(ch->length));
-		if (ch_end > skb_tail_pointer(skb))
-			return sctp_sf_violation_chunklen(net, ep, asoc, type, arg,
-						  commands);
 
 		ch = (sctp_chunkhdr_t *) ch_end;
 	} while (ch_end < skb_tail_pointer(skb));
```
