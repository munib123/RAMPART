# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2172_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2172_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 123-163 of the vulnerable file.

{
	struct sctp_chunk *chunk;
	sctp_chunkhdr_t *ch = NULL;

	/* The assumption is that we are safe to process the chunks
	 * at this time.
	 */

	if ((chunk = queue->in_progress)) {
		/* There is a packet that we have been working on.
		 * Any post processing work to do before we move on?
		 */
		if (chunk->singleton ||
		    chunk->end_of_packet ||
		    chunk->pdiscard) {
			sctp_chunk_free(chunk);
			chunk = queue->in_progress = NULL;
		} else {
			/* Nothing to do. Next chunk in the packet, please. */
			ch = (sctp_chunkhdr_t *) chunk->chunk_end;

			/* Force chunk->skb->data to chunk->chunk_end.  */
			skb_pull(chunk->skb,
				 chunk->chunk_end - chunk->skb->data);

			/* Verify that we have at least chunk headers
			 * worth of buffer left.
			 */
			if (skb_headlen(chunk->skb) < sizeof(sctp_chunkhdr_t)) {
				sctp_chunk_free(chunk);
				chunk = queue->in_progress = NULL;
			}
		}
	}

	/* Do we need to take the next packet out of the queue to process? */
	if (!chunk) {
		struct list_head *entry;

		/* Is the queue empty?  */
		if (list_empty(&queue->in_chunk_list))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -140,18 +140,9 @@
 		} else {
 			/* Nothing to do. Next chunk in the packet, please. */
 			ch = (sctp_chunkhdr_t *) chunk->chunk_end;
-
 			/* Force chunk->skb->data to chunk->chunk_end.  */
-			skb_pull(chunk->skb,
-				 chunk->chunk_end - chunk->skb->data);
-
-			/* Verify that we have at least chunk headers
-			 * worth of buffer left.
-			 */
-			if (skb_headlen(chunk->skb) < sizeof(sctp_chunkhdr_t)) {
-				sctp_chunk_free(chunk);
-				chunk = queue->in_progress = NULL;
-			}
+			skb_pull(chunk->skb, chunk->chunk_end - chunk->skb->data);
+			/* We are guaranteed to pull a SCTP header. */
 		}
 	}
 
@@ -187,24 +178,14 @@
 	skb_pull(chunk->skb, sizeof(sctp_chunkhdr_t));
 	chunk->subh.v = NULL; /* Subheader is no longer valid.  */
 
-	if (chunk->chunk_end < skb_tail_pointer(chunk->skb)) {
+	if (chunk->chunk_end + sizeof(sctp_chunkhdr_t) <
+	    skb_tail_pointer(chunk->skb)) {
 		/* This is not a singleton */
 		chunk->singleton = 0;
 	} else if (chunk->chunk_end > skb_tail_pointer(chunk->skb)) {
-		/* RFC 2960, Section 6.10  Bundling
-		 *
-		 * Partial chunks MUST NOT be placed in an SCTP packet.
-		 * If the receiver detects a partial chunk, it MUST drop
-		 * the chunk.
-		 *
-		 * Since the end of the chunk is past the end of our buffer
-		 * (which contains the whole packet, we can freely discard
-		 * the whole packet.
-		 */
-		sctp_chunk_free(chunk);
-		chunk = queue->in_progress = NULL;
-
-		return NULL;
+		/* Discard inside state machine. */
+		chunk->pdiscard = 1;
+		chunk->chunk_end = skb_tail_pointer(chunk->skb);
 	} else {
 		/* We are at the end of the packet, so mark the chunk
 		 * in case we need to send a SACK.
```
