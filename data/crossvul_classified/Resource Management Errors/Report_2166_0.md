# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2166_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2166_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 231-273 of the vulnerable file.

						   const struct sctp_chunk *);
struct sctp_chunk *sctp_make_heartbeat(const struct sctp_association *,
				  const struct sctp_transport *);
struct sctp_chunk *sctp_make_heartbeat_ack(const struct sctp_association *,
				      const struct sctp_chunk *,
				      const void *payload,
				      const size_t paylen);
struct sctp_chunk *sctp_make_op_error(const struct sctp_association *,
				 const struct sctp_chunk *chunk,
				 __be16 cause_code,
				 const void *payload,
				 size_t paylen,
				 size_t reserve_tail);

struct sctp_chunk *sctp_make_asconf_update_ip(struct sctp_association *,
					      union sctp_addr *,
					      struct sockaddr *,
					      int, __be16);
struct sctp_chunk *sctp_make_asconf_set_prim(struct sctp_association *asoc,
					     union sctp_addr *addr);
int sctp_verify_asconf(const struct sctp_association *asoc,
		       struct sctp_paramhdr *param_hdr, void *chunk_end,
		       struct sctp_paramhdr **errp);
struct sctp_chunk *sctp_process_asconf(struct sctp_association *asoc,
				       struct sctp_chunk *asconf);
int sctp_process_asconf_ack(struct sctp_association *asoc,
			    struct sctp_chunk *asconf_ack);
struct sctp_chunk *sctp_make_fwdtsn(const struct sctp_association *asoc,
				    __u32 new_cum_tsn, size_t nstreams,
				    struct sctp_fwdtsn_skip *skiplist);
struct sctp_chunk *sctp_make_auth(const struct sctp_association *asoc);

void sctp_chunk_assign_tsn(struct sctp_chunk *);
void sctp_chunk_assign_ssn(struct sctp_chunk *);

/* Prototypes for statetable processing. */

int sctp_do_sm(struct net *net, sctp_event_t event_type, sctp_subtype_t subtype,
	       sctp_state_t state,
               struct sctp_endpoint *,
               struct sctp_association *asoc,
               void *event_arg,
	       gfp_t gfp);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -248,9 +248,9 @@
 					      int, __be16);
 struct sctp_chunk *sctp_make_asconf_set_prim(struct sctp_association *asoc,
 					     union sctp_addr *addr);
-int sctp_verify_asconf(const struct sctp_association *asoc,
-		       struct sctp_paramhdr *param_hdr, void *chunk_end,
-		       struct sctp_paramhdr **errp);
+bool sctp_verify_asconf(const struct sctp_association *asoc,
+			struct sctp_chunk *chunk, bool addr_param_needed,
+			struct sctp_paramhdr **errp);
 struct sctp_chunk *sctp_process_asconf(struct sctp_association *asoc,
 				       struct sctp_chunk *asconf);
 int sctp_process_asconf_ack(struct sctp_association *asoc,
```
