# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2166_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2166_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 3574-3614 of the vulnerable file.

	 * to a restarted association. So the packet is treated as an OOTB
	 * packet and the state function that handles OOTB SHUTDOWN_ACK is
	 * called with a NULL association.
	 */
	SCTP_INC_STATS(net, SCTP_MIB_OUTOFBLUES);

	return sctp_sf_shut_8_4_5(net, ep, NULL, type, arg, commands);
}

/* ADDIP Section 4.2 Upon reception of an ASCONF Chunk.  */
sctp_disposition_t sctp_sf_do_asconf(struct net *net,
				     const struct sctp_endpoint *ep,
				     const struct sctp_association *asoc,
				     const sctp_subtype_t type, void *arg,
				     sctp_cmd_seq_t *commands)
{
	struct sctp_chunk	*chunk = arg;
	struct sctp_chunk	*asconf_ack = NULL;
	struct sctp_paramhdr	*err_param = NULL;
	sctp_addiphdr_t		*hdr;
	union sctp_addr_param	*addr_param;
	__u32			serial;
	int			length;

	if (!sctp_vtag_verify(chunk, asoc)) {
		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_BAD_TAG,
				SCTP_NULL());
		return sctp_sf_pdiscard(net, ep, asoc, type, arg, commands);
	}

	/* ADD-IP: Section 4.1.1
	 * This chunk MUST be sent in an authenticated way by using
	 * the mechanism defined in [I-D.ietf-tsvwg-sctp-auth]. If this chunk
	 * is received unauthenticated it MUST be silently discarded as
	 * described in [I-D.ietf-tsvwg-sctp-auth].
	 */
	if (!net->sctp.addip_noauth && !chunk->auth)
		return sctp_sf_discard_chunk(net, ep, asoc, type, arg, commands);

	/* Make sure that the ASCONF ADDIP chunk has a valid length.  */
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_addip_chunk_t)))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3591,9 +3591,7 @@
 	struct sctp_chunk	*asconf_ack = NULL;
 	struct sctp_paramhdr	*err_param = NULL;
 	sctp_addiphdr_t		*hdr;
-	union sctp_addr_param	*addr_param;
 	__u32			serial;
-	int			length;
 
 	if (!sctp_vtag_verify(chunk, asoc)) {
 		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_BAD_TAG,
@@ -3618,17 +3616,8 @@
 	hdr = (sctp_addiphdr_t *)chunk->skb->data;
 	serial = ntohl(hdr->serial);
 
-	addr_param = (union sctp_addr_param *)hdr->params;
-	length = ntohs(addr_param->p.length);
-	if (length < sizeof(sctp_paramhdr_t))
-		return sctp_sf_violation_paramlen(net, ep, asoc, type, arg,
-			   (void *)addr_param, commands);
-
 	/* Verify the ASCONF chunk before processing it. */
-	if (!sctp_verify_asconf(asoc,
-			    (sctp_paramhdr_t *)((void *)addr_param + length),
-			    (void *)chunk->chunk_end,
-			    &err_param))
+	if (!sctp_verify_asconf(asoc, chunk, true, &err_param))
 		return sctp_sf_violation_paramlen(net, ep, asoc, type, arg,
 						  (void *)err_param, commands);
 
@@ -3745,10 +3734,7 @@
 	rcvd_serial = ntohl(addip_hdr->serial);
 
 	/* Verify the ASCONF-ACK chunk before processing it. */
-	if (!sctp_verify_asconf(asoc,
-	    (sctp_paramhdr_t *)addip_hdr->params,
-	    (void *)asconf_ack->chunk_end,
-	    &err_param))
+	if (!sctp_verify_asconf(asoc, asconf_ack, false, &err_param))
 		return sctp_sf_violation_paramlen(net, ep, asoc, type, arg,
 			   (void *)err_param, commands);
 
```
