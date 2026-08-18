# CrossVul Fix Pair: Improperly Implemented Security Check for Standard in c
**Pair ID:** 3239_0
**Vulnerability Class:** Improperly Implemented Security Check for Standard
**CWE:** CWE-358
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3239_0`)

## Vulnerability Information & PoC

## Description
Improperly Implemented Security Check for Standard - The product does not implement or incorrectly implements one or more security-relevant checks as specified by the design of a standardized algorithm, protocol, or technique.

## Vulnerable Code
```c
Lines 75-115 of the vulnerable file.

}

#define DefragTrackerIncrUsecnt(dt) \
    SC_ATOMIC_ADD((dt)->use_cnt, 1)
#define DefragTrackerDecrUsecnt(dt) \
    SC_ATOMIC_SUB((dt)->use_cnt, 1)

static void DefragTrackerInit(DefragTracker *dt, Packet *p)
{
    /* copy address */
    COPY_ADDRESS(&p->src, &dt->src_addr);
    COPY_ADDRESS(&p->dst, &dt->dst_addr);

    if (PKT_IS_IPV4(p)) {
        dt->id = (int32_t)IPV4_GET_IPID(p);
        dt->af = AF_INET;
    } else {
        dt->id = (int32_t)IPV6_EXTHDR_GET_FH_ID(p);
        dt->af = AF_INET6;
    }
    dt->vlan_id[0] = p->vlan_id[0];
    dt->vlan_id[1] = p->vlan_id[1];
    dt->policy = DefragGetOsPolicy(p);
    dt->host_timeout = DefragPolicyGetHostTimeout(p);
    dt->remove = 0;
    dt->seen_last = 0;

    TAILQ_INIT(&dt->frags);
    (void) DefragTrackerIncrUsecnt(dt);
}

void DefragTrackerRelease(DefragTracker *t)
{
    (void) DefragTrackerDecrUsecnt(t);
    SCMutexUnlock(&t->lock);
}

void DefragTrackerClearMemory(DefragTracker *dt)
{
    DefragTrackerFreeFrags(dt);
    SC_ATOMIC_DESTROY(dt->use_cnt);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,6 +92,7 @@
         dt->id = (int32_t)IPV6_EXTHDR_GET_FH_ID(p);
         dt->af = AF_INET6;
     }
+    dt->proto = IP_GET_IPPROTO(p);
     dt->vlan_id[0] = p->vlan_id[0];
     dt->vlan_id[1] = p->vlan_id[1];
     dt->policy = DefragGetOsPolicy(p);
@@ -406,6 +407,7 @@
        CMP_ADDR(&(d1)->dst_addr, &(d2)->dst)) || \
       (CMP_ADDR(&(d1)->src_addr, &(d2)->dst) && \
        CMP_ADDR(&(d1)->dst_addr, &(d2)->src))) && \
+     (d1)->proto == IP_GET_IPPROTO(p) &&        \
      (d1)->id == (id) && \
      (d1)->vlan_id[0] == (d2)->vlan_id[0] && \
      (d1)->vlan_id[1] == (d2)->vlan_id[1])
```
