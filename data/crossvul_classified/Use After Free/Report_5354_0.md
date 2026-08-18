# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5354_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5354_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 3631-3672 of the vulnerable file.

			optname == PACKET_TX_RING);
	}
	case PACKET_COPY_THRESH:
	{
		int val;

		if (optlen != sizeof(val))
			return -EINVAL;
		if (copy_from_user(&val, optval, sizeof(val)))
			return -EFAULT;

		pkt_sk(sk)->copy_thresh = val;
		return 0;
	}
	case PACKET_VERSION:
	{
		int val;

		if (optlen != sizeof(val))
			return -EINVAL;
		if (po->rx_ring.pg_vec || po->tx_ring.pg_vec)
			return -EBUSY;
		if (copy_from_user(&val, optval, sizeof(val)))
			return -EFAULT;
		switch (val) {
		case TPACKET_V1:
		case TPACKET_V2:
		case TPACKET_V3:
			po->tp_version = val;
			return 0;
		default:
			return -EINVAL;
		}
	}
	case PACKET_RESERVE:
	{
		unsigned int val;

		if (optlen != sizeof(val))
			return -EINVAL;
		if (po->rx_ring.pg_vec || po->tx_ring.pg_vec)
			return -EBUSY;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3648,19 +3648,25 @@
 
 		if (optlen != sizeof(val))
 			return -EINVAL;
-		if (po->rx_ring.pg_vec || po->tx_ring.pg_vec)
-			return -EBUSY;
 		if (copy_from_user(&val, optval, sizeof(val)))
 			return -EFAULT;
 		switch (val) {
 		case TPACKET_V1:
 		case TPACKET_V2:
 		case TPACKET_V3:
-			po->tp_version = val;
-			return 0;
+			break;
 		default:
 			return -EINVAL;
 		}
+		lock_sock(sk);
+		if (po->rx_ring.pg_vec || po->tx_ring.pg_vec) {
+			ret = -EBUSY;
+		} else {
+			po->tp_version = val;
+			ret = 0;
+		}
+		release_sock(sk);
+		return ret;
 	}
 	case PACKET_RESERVE:
 	{
@@ -4164,6 +4170,7 @@
 	/* Added to avoid minimal code churn */
 	struct tpacket_req *req = &req_u->req;
 
+	lock_sock(sk);
 	/* Opening a Tx-ring is NOT supported in TPACKET_V3 */
 	if (!closing && tx_ring && (po->tp_version > TPACKET_V2)) {
 		net_warn_ratelimited("Tx-ring is not supported.\n");
@@ -4245,7 +4252,6 @@
 			goto out;
 	}
 
-	lock_sock(sk);
 
 	/* Detach socket from network */
 	spin_lock(&po->bind_lock);
@@ -4294,11 +4300,11 @@
 		if (!tx_ring)
 			prb_shutdown_retire_blk_timer(po, rb_queue);
 	}
-	release_sock(sk);
 
 	if (pg_vec)
 		free_pg_vec(pg_vec, order, req->tp_block_nr);
 out:
+	release_sock(sk);
 	return err;
 }
 
```
