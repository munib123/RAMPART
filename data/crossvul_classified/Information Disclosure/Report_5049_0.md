# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5049_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5049_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 609-649 of the vulnerable file.

		rc = -EAGAIN;
		if (!timeo)
			break;
		rc = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		rc = 0;
		if (sk_wait_data(sk, &timeo, NULL))
			break;
	}
	return rc;
}

static void llc_cmsg_rcv(struct msghdr *msg, struct sk_buff *skb)
{
	struct llc_sock *llc = llc_sk(skb->sk);

	if (llc->cmsg_flags & LLC_CMSG_PKTINFO) {
		struct llc_pktinfo info;

		info.lpi_ifindex = llc_sk(skb->sk)->dev->ifindex;
		llc_pdu_decode_dsap(skb, &info.lpi_sap);
		llc_pdu_decode_da(skb, info.lpi_mac);
		put_cmsg(msg, SOL_LLC, LLC_OPT_PKTINFO, sizeof(info), &info);
	}
}

/**
 *	llc_ui_accept - accept a new incoming connection.
 *	@sock: Socket which connections arrive on.
 *	@newsock: Socket to move incoming connection to.
 *	@flags: User specified operational flags.
 *
 *	Accept a new incoming connection.
 *	Returns 0 upon success, negative otherwise.
 */
static int llc_ui_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct sock *sk = sock->sk, *newsk;
	struct llc_sock *llc, *newllc;
	struct sk_buff *skb;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -626,6 +626,7 @@
 	if (llc->cmsg_flags & LLC_CMSG_PKTINFO) {
 		struct llc_pktinfo info;
 
+		memset(&info, 0, sizeof(info));
 		info.lpi_ifindex = llc_sk(skb->sk)->dev->ifindex;
 		llc_pdu_decode_dsap(skb, &info.lpi_sap);
 		llc_pdu_decode_da(skb, info.lpi_mac);
```
