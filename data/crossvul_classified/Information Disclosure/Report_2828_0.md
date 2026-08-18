# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2828_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2828_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 822-862 of the vulnerable file.

static int max_sectors_bytes(struct request_queue *q)
{
	unsigned int max_sectors = queue_max_sectors(q);

	max_sectors = min_t(unsigned int, max_sectors, INT_MAX >> 9);

	return max_sectors << 9;
}

static void
sg_fill_request_table(Sg_fd *sfp, sg_req_info_t *rinfo)
{
	Sg_request *srp;
	int val;
	unsigned int ms;

	val = 0;
	list_for_each_entry(srp, &sfp->rq_list, entry) {
		if (val > SG_MAX_QUEUE)
			break;
		memset(&rinfo[val], 0, SZ_SG_REQ_INFO);
		rinfo[val].req_state = srp->done + 1;
		rinfo[val].problem =
			srp->header.masked_status &
			srp->header.host_status &
			srp->header.driver_status;
		if (srp->done)
			rinfo[val].duration =
				srp->header.duration;
		else {
			ms = jiffies_to_msecs(jiffies);
			rinfo[val].duration =
				(ms > srp->header.duration) ?
				(ms - srp->header.duration) : 0;
		}
		rinfo[val].orphan = srp->orphan;
		rinfo[val].sg_io_owned = srp->sg_io_owned;
		rinfo[val].pack_id = srp->header.pack_id;
		rinfo[val].usr_ptr = srp->header.usr_ptr;
		val++;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -839,7 +839,6 @@
 	list_for_each_entry(srp, &sfp->rq_list, entry) {
 		if (val > SG_MAX_QUEUE)
 			break;
-		memset(&rinfo[val], 0, SZ_SG_REQ_INFO);
 		rinfo[val].req_state = srp->done + 1;
 		rinfo[val].problem =
 			srp->header.masked_status &
@@ -1047,8 +1046,8 @@
 		else {
 			sg_req_info_t *rinfo;
 
-			rinfo = kmalloc(SZ_SG_REQ_INFO * SG_MAX_QUEUE,
-								GFP_KERNEL);
+			rinfo = kzalloc(SZ_SG_REQ_INFO * SG_MAX_QUEUE,
+					GFP_KERNEL);
 			if (!rinfo)
 				return -ENOMEM;
 			read_lock_irqsave(&sfp->rq_list_lock, iflags);
```
