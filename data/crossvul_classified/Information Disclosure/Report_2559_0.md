# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2559_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2559_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1416-1456 of the vulnerable file.

	msleep(1); /* back off a bit */
	return -EIO;

 fail_put_bio:
	for (i = 0; i < nbio; i++)
		bio_put(biolist[i]);
	atomic_set(&pending_req->pendcnt, 1);
	__end_block_io_op(pending_req, -EINVAL);
	msleep(1); /* back off a bit */
	return -EIO;
}



/*
 * Put a response on the ring on how the operation fared.
 */
static void make_response(struct xen_blkif_ring *ring, u64 id,
			  unsigned short op, int st)
{
	struct blkif_response  resp;
	unsigned long     flags;
	union blkif_back_rings *blk_rings;
	int notify;

	resp.id        = id;
	resp.operation = op;
	resp.status    = st;

	spin_lock_irqsave(&ring->blk_ring_lock, flags);
	blk_rings = &ring->blk_rings;
	/* Place on the response ring for the relevant domain. */
	switch (ring->blkif->blk_protocol) {
	case BLKIF_PROTOCOL_NATIVE:
		memcpy(RING_GET_RESPONSE(&blk_rings->native, blk_rings->native.rsp_prod_pvt),
		       &resp, sizeof(resp));
		break;
	case BLKIF_PROTOCOL_X86_32:
		memcpy(RING_GET_RESPONSE(&blk_rings->x86_32, blk_rings->x86_32.rsp_prod_pvt),
		       &resp, sizeof(resp));
		break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1433,34 +1433,35 @@
 static void make_response(struct xen_blkif_ring *ring, u64 id,
 			  unsigned short op, int st)
 {
-	struct blkif_response  resp;
+	struct blkif_response *resp;
 	unsigned long     flags;
 	union blkif_back_rings *blk_rings;
 	int notify;
-
-	resp.id        = id;
-	resp.operation = op;
-	resp.status    = st;
 
 	spin_lock_irqsave(&ring->blk_ring_lock, flags);
 	blk_rings = &ring->blk_rings;
 	/* Place on the response ring for the relevant domain. */
 	switch (ring->blkif->blk_protocol) {
 	case BLKIF_PROTOCOL_NATIVE:
-		memcpy(RING_GET_RESPONSE(&blk_rings->native, blk_rings->native.rsp_prod_pvt),
-		       &resp, sizeof(resp));
+		resp = RING_GET_RESPONSE(&blk_rings->native,
+					 blk_rings->native.rsp_prod_pvt);
 		break;
 	case BLKIF_PROTOCOL_X86_32:
-		memcpy(RING_GET_RESPONSE(&blk_rings->x86_32, blk_rings->x86_32.rsp_prod_pvt),
-		       &resp, sizeof(resp));
+		resp = RING_GET_RESPONSE(&blk_rings->x86_32,
+					 blk_rings->x86_32.rsp_prod_pvt);
 		break;
 	case BLKIF_PROTOCOL_X86_64:
-		memcpy(RING_GET_RESPONSE(&blk_rings->x86_64, blk_rings->x86_64.rsp_prod_pvt),
-		       &resp, sizeof(resp));
+		resp = RING_GET_RESPONSE(&blk_rings->x86_64,
+					 blk_rings->x86_64.rsp_prod_pvt);
 		break;
 	default:
 		BUG();
 	}
+
+	resp->id        = id;
+	resp->operation = op;
+	resp->status    = st;
+
 	blk_rings->common.rsp_prod_pvt++;
 	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&blk_rings->common, notify);
 	spin_unlock_irqrestore(&ring->blk_ring_lock, flags);
```
