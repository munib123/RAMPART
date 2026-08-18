# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3176_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3176_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 99-142 of the vulnerable file.


static void ip_cmsg_recv_fragsize(struct msghdr *msg, struct sk_buff *skb)
{
	int val;

	if (IPCB(skb)->frag_max_size == 0)
		return;

	val = IPCB(skb)->frag_max_size;
	put_cmsg(msg, SOL_IP, IP_RECVFRAGSIZE, sizeof(val), &val);
}

static void ip_cmsg_recv_checksum(struct msghdr *msg, struct sk_buff *skb,
				  int tlen, int offset)
{
	__wsum csum = skb->csum;

	if (skb->ip_summed != CHECKSUM_COMPLETE)
		return;

	if (offset != 0)
		csum = csum_sub(csum,
				csum_partial(skb_transport_header(skb) + tlen,
					     offset, 0));

	put_cmsg(msg, SOL_IP, IP_CHECKSUM, sizeof(__wsum), &csum);
}

static void ip_cmsg_recv_security(struct msghdr *msg, struct sk_buff *skb)
{
	char *secdata;
	u32 seclen, secid;
	int err;

	err = security_socket_getpeersec_dgram(NULL, skb, &secid);
	if (err)
		return;

	err = security_secid_to_secctx(secid, &secdata, &seclen);
	if (err)
		return;

	put_cmsg(msg, SOL_IP, SCM_SECURITY, seclen, secdata);
	security_release_secctx(secdata, seclen);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,10 +116,10 @@
 	if (skb->ip_summed != CHECKSUM_COMPLETE)
 		return;
 
-	if (offset != 0)
-		csum = csum_sub(csum,
-				csum_partial(skb_transport_header(skb) + tlen,
-					     offset, 0));
+	if (offset != 0) {
+		int tend_off = skb_transport_offset(skb) + tlen;
+		csum = csum_sub(csum, skb_checksum(skb, tend_off, offset, 0));
+	}
 
 	put_cmsg(msg, SOL_IP, IP_CHECKSUM, sizeof(__wsum), &csum);
 }
```
