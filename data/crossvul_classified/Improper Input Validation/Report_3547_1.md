# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3547_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3547_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 961-1001 of the vulnerable file.

			srose->srose_digis[n] = rose->dest_digis[n];
	} else {
		srose->srose_family = AF_ROSE;
		srose->srose_addr   = rose->source_addr;
		srose->srose_call   = rose->source_call;
		srose->srose_ndigis = rose->source_ndigis;
		for (n = 0; n < rose->source_ndigis; n++)
			srose->srose_digis[n] = rose->source_digis[n];
	}

	*uaddr_len = sizeof(struct full_sockaddr_rose);
	return 0;
}

int rose_rx_call_request(struct sk_buff *skb, struct net_device *dev, struct rose_neigh *neigh, unsigned int lci)
{
	struct sock *sk;
	struct sock *make;
	struct rose_sock *make_rose;
	struct rose_facilities_struct facilities;
	int n, len;

	skb->sk = NULL;		/* Initially we don't know who it's for */

	/*
	 *	skb->data points to the rose frame start
	 */
	memset(&facilities, 0x00, sizeof(struct rose_facilities_struct));

	len  = (((skb->data[3] >> 4) & 0x0F) + 1) >> 1;
	len += (((skb->data[3] >> 0) & 0x0F) + 1) >> 1;
	if (!rose_parse_facilities(skb->data + len + 4, &facilities)) {
		rose_transmit_clear_request(neigh, lci, ROSE_INVALID_FACILITY, 76);
		return 0;
	}

	sk = rose_find_listener(&facilities.source_addr, &facilities.source_call);

	/*
	 * We can't accept the Call Request.
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -978,7 +978,7 @@
 	struct sock *make;
 	struct rose_sock *make_rose;
 	struct rose_facilities_struct facilities;
-	int n, len;
+	int n;
 
 	skb->sk = NULL;		/* Initially we don't know who it's for */
 
@@ -987,9 +987,9 @@
 	 */
 	memset(&facilities, 0x00, sizeof(struct rose_facilities_struct));
 
-	len  = (((skb->data[3] >> 4) & 0x0F) + 1) >> 1;
-	len += (((skb->data[3] >> 0) & 0x0F) + 1) >> 1;
-	if (!rose_parse_facilities(skb->data + len + 4, &facilities)) {
+	if (!rose_parse_facilities(skb->data + ROSE_CALL_REQ_FACILITIES_OFF,
+				   skb->len - ROSE_CALL_REQ_FACILITIES_OFF,
+				   &facilities)) {
 		rose_transmit_clear_request(neigh, lci, ROSE_INVALID_FACILITY, 76);
 		return 0;
 	}
```
