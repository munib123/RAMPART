# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2171_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2171_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 409-449 of the vulnerable file.

	int frag = pmtu;

	frag -= sp->pf->af->net_header_len;
	frag -= sizeof(struct sctphdr) + sizeof(struct sctp_data_chunk);

	if (asoc->user_frag)
		frag = min_t(int, frag, asoc->user_frag);

	frag = min_t(int, frag, SCTP_MAX_CHUNK_LEN);

	return frag;
}

static inline void sctp_assoc_pending_pmtu(struct sock *sk, struct sctp_association *asoc)
{

	sctp_assoc_sync_pmtu(sk, asoc);
	asoc->pmtu_pending = 0;
}

/* Walk through a list of TLV parameters.  Don't trust the
 * individual parameter lengths and instead depend on
 * the chunk length to indicate when to stop.  Make sure
 * there is room for a param header too.
 */
#define sctp_walk_params(pos, chunk, member)\
_sctp_walk_params((pos), (chunk), ntohs((chunk)->chunk_hdr.length), member)

#define _sctp_walk_params(pos, chunk, end, member)\
for (pos.v = chunk->member;\
     pos.v <= (void *)chunk + end - ntohs(pos.p->length) &&\
     ntohs(pos.p->length) >= sizeof(sctp_paramhdr_t);\
     pos.v += WORD_ROUND(ntohs(pos.p->length)))

#define sctp_walk_errors(err, chunk_hdr)\
_sctp_walk_errors((err), (chunk_hdr), ntohs((chunk_hdr)->length))

#define _sctp_walk_errors(err, chunk_hdr, end)\
for (err = (sctp_errhdr_t *)((void *)chunk_hdr + \
	    sizeof(sctp_chunkhdr_t));\
     (void *)err <= (void *)chunk_hdr + end - ntohs(err->length) &&\
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -426,6 +426,11 @@
 	asoc->pmtu_pending = 0;
 }
 
+static inline bool sctp_chunk_pending(const struct sctp_chunk *chunk)
+{
+	return !list_empty(&chunk->list);
+}
+
 /* Walk through a list of TLV parameters.  Don't trust the
  * individual parameter lengths and instead depend on
  * the chunk length to indicate when to stop.  Make sure
```
