# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3547_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3547_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 844-884 of the vulnerable file.

			rose_del_route_by_neigh(rose_neigh);
			rose_kill_by_neigh(rose_neigh);
		}
	}
}

/*
 *	Route a frame to an appropriate AX.25 connection.
 */
int rose_route_frame(struct sk_buff *skb, ax25_cb *ax25)
{
	struct rose_neigh *rose_neigh, *new_neigh;
	struct rose_route *rose_route;
	struct rose_facilities_struct facilities;
	rose_address *src_addr, *dest_addr;
	struct sock *sk;
	unsigned short frametype;
	unsigned int lci, new_lci;
	unsigned char cause, diagnostic;
	struct net_device *dev;
	int len, res = 0;
	char buf[11];

#if 0
	if (call_in_firewall(PF_ROSE, skb->dev, skb->data, NULL, &skb) != FW_ACCEPT)
		return res;
#endif

	frametype = skb->data[2];
	lci = ((skb->data[0] << 8) & 0xF00) + ((skb->data[1] << 0) & 0x0FF);
	src_addr  = (rose_address *)(skb->data + 9);
	dest_addr = (rose_address *)(skb->data + 4);

	spin_lock_bh(&rose_neigh_list_lock);
	spin_lock_bh(&rose_route_list_lock);

	rose_neigh = rose_neigh_list;
	while (rose_neigh != NULL) {
		if (ax25cmp(&ax25->dest_addr, &rose_neigh->callsign) == 0 &&
		    ax25->ax25_dev->dev == rose_neigh->dev)
			break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -861,7 +861,7 @@
 	unsigned int lci, new_lci;
 	unsigned char cause, diagnostic;
 	struct net_device *dev;
-	int len, res = 0;
+	int res = 0;
 	char buf[11];
 
 #if 0
@@ -869,10 +869,17 @@
 		return res;
 #endif
 
+	if (skb->len < ROSE_MIN_LEN)
+		return res;
 	frametype = skb->data[2];
 	lci = ((skb->data[0] << 8) & 0xF00) + ((skb->data[1] << 0) & 0x0FF);
-	src_addr  = (rose_address *)(skb->data + 9);
-	dest_addr = (rose_address *)(skb->data + 4);
+	if (frametype == ROSE_CALL_REQUEST &&
+	    (skb->len <= ROSE_CALL_REQ_FACILITIES_OFF ||
+	     skb->data[ROSE_CALL_REQ_ADDR_LEN_OFF] !=
+	     ROSE_CALL_REQ_ADDR_LEN_VAL))
+		return res;
+	src_addr  = (rose_address *)(skb->data + ROSE_CALL_REQ_SRC_ADDR_OFF);
+	dest_addr = (rose_address *)(skb->data + ROSE_CALL_REQ_DEST_ADDR_OFF);
 
 	spin_lock_bh(&rose_neigh_list_lock);
 	spin_lock_bh(&rose_route_list_lock);
@@ -1010,12 +1017,11 @@
 		goto out;
 	}
 
-	len  = (((skb->data[3] >> 4) & 0x0F) + 1) >> 1;
-	len += (((skb->data[3] >> 0) & 0x0F) + 1) >> 1;
-
 	memset(&facilities, 0x00, sizeof(struct rose_facilities_struct));
 
-	if (!rose_parse_facilities(skb->data + len + 4, &facilities)) {
+	if (!rose_parse_facilities(skb->data + ROSE_CALL_REQ_FACILITIES_OFF,
+				   skb->len - ROSE_CALL_REQ_FACILITIES_OFF,
+				   &facilities)) {
 		rose_transmit_clear_request(rose_neigh, lci, ROSE_INVALID_FACILITY, 76);
 		goto out;
 	}
```
