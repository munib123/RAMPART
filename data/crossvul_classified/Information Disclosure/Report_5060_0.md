# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5060_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5060_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 260-300 of the vulnerable file.

	buffer[0] = len - 1;

	return len;
}

/*
 *	Try to reach a compromise on a set of facilities.
 *
 *	The only real problem is with reverse charging.
 */
int x25_negotiate_facilities(struct sk_buff *skb, struct sock *sk,
		struct x25_facilities *new, struct x25_dte_facilities *dte)
{
	struct x25_sock *x25 = x25_sk(sk);
	struct x25_facilities *ours = &x25->facilities;
	struct x25_facilities theirs;
	int len;

	memset(&theirs, 0, sizeof(theirs));
	memcpy(new, ours, sizeof(*new));

	len = x25_parse_facilities(skb, &theirs, dte, &x25->vc_facil_mask);
	if (len < 0)
		return len;

	/*
	 *	They want reverse charging, we won't accept it.
	 */
	if ((theirs.reverse & 0x01 ) && (ours->reverse & 0x01)) {
		SOCK_DEBUG(sk, "X.25: rejecting reverse charging request\n");
		return -1;
	}

	new->reverse = theirs.reverse;

	if (theirs.throughput) {
		int theirs_in =  theirs.throughput & 0x0f;
		int theirs_out = theirs.throughput & 0xf0;
		int ours_in  = ours->throughput & 0x0f;
		int ours_out = ours->throughput & 0xf0;
		if (!ours_in || theirs_in < ours_in) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -277,6 +277,7 @@
 
 	memset(&theirs, 0, sizeof(theirs));
 	memcpy(new, ours, sizeof(*new));
+	memset(dte, 0, sizeof(*dte));
 
 	len = x25_parse_facilities(skb, &theirs, dte, &x25->vc_facil_mask);
 	if (len < 0)
```
