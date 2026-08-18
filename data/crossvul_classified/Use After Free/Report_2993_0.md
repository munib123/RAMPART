# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2993_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2993_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 87-127 of the vulnerable file.

	int len, tcp_hdrlen;
	unsigned int i;
	__be16 oldval;
	u16 newmss;
	u8 *opt;

	/* This is a fragment, no TCP header is available */
	if (par->fragoff != 0)
		return 0;

	if (!skb_make_writable(skb, skb->len))
		return -1;

	len = skb->len - tcphoff;
	if (len < (int)sizeof(struct tcphdr))
		return -1;

	tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
	tcp_hdrlen = tcph->doff * 4;

	if (len < tcp_hdrlen)
		return -1;

	if (info->mss == XT_TCPMSS_CLAMP_PMTU) {
		struct net *net = xt_net(par);
		unsigned int in_mtu = tcpmss_reverse_mtu(net, skb, family);
		unsigned int min_mtu = min(dst_mtu(skb_dst(skb)), in_mtu);

		if (min_mtu <= minlen) {
			net_err_ratelimited("unknown or invalid path-MTU (%u)\n",
					    min_mtu);
			return -1;
		}
		newmss = min_mtu - minlen;
	} else
		newmss = info->mss;

	opt = (u_int8_t *)tcph;
	for (i = sizeof(struct tcphdr); i <= tcp_hdrlen - TCPOLEN_MSS; i += optlen(opt, i)) {
		if (opt[i] == TCPOPT_MSS && opt[i+1] == TCPOLEN_MSS) {
			u_int16_t oldmss;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,7 +104,7 @@
 	tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
 	tcp_hdrlen = tcph->doff * 4;
 
-	if (len < tcp_hdrlen)
+	if (len < tcp_hdrlen || tcp_hdrlen < sizeof(struct tcphdr))
 		return -1;
 
 	if (info->mss == XT_TCPMSS_CLAMP_PMTU) {
@@ -150,6 +150,10 @@
 	 * itself too large. Accept the packet unmodified instead.
 	 */
 	if (len > tcp_hdrlen)
+		return 0;
+
+	/* tcph->doff has 4 bits, do not wrap it to 0 */
+	if (tcp_hdrlen >= 15 * 4)
 		return 0;
 
 	/*
```
