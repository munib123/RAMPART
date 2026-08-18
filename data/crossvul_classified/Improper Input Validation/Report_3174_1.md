# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3174_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3174_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 273-313 of the vulnerable file.

	ev->type      = LLC_SAP_EV_TYPE_PRIM;
	ev->prim      = LLC_XID_PRIM;
	ev->prim_type = LLC_PRIM_TYPE_REQ;
	llc_sap_state_process(sap, skb);
}

/**
 *	llc_sap_rcv - sends received pdus to the sap state machine
 *	@sap: current sap component structure.
 *	@skb: received frame.
 *
 *	Sends received pdus to the sap state machine.
 */
static void llc_sap_rcv(struct llc_sap *sap, struct sk_buff *skb,
			struct sock *sk)
{
	struct llc_sap_state_ev *ev = llc_sap_ev(skb);

	ev->type   = LLC_SAP_EV_TYPE_PDU;
	ev->reason = 0;
	skb->sk = sk;
	llc_sap_state_process(sap, skb);
}

static inline bool llc_dgram_match(const struct llc_sap *sap,
				   const struct llc_addr *laddr,
				   const struct sock *sk)
{
     struct llc_sock *llc = llc_sk(sk);

     return sk->sk_type == SOCK_DGRAM &&
	  llc->laddr.lsap == laddr->lsap &&
	  ether_addr_equal(llc->laddr.mac, laddr->mac);
}

/**
 *	llc_lookup_dgram - Finds dgram socket for the local sap/mac
 *	@sap: SAP
 *	@laddr: address of local LLC (MAC + SAP)
 *
 *	Search socket list of the SAP and finds connection using the local
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -290,7 +290,10 @@
 
 	ev->type   = LLC_SAP_EV_TYPE_PDU;
 	ev->reason = 0;
+	skb_orphan(skb);
+	sock_hold(sk);
 	skb->sk = sk;
+	skb->destructor = sock_efree;
 	llc_sap_state_process(sap, skb);
 }
 
```
