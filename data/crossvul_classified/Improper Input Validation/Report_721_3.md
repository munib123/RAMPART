# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 721_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `721_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 888-928 of the vulnerable file.

        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);   \
    } while (0)

#define TUNNEL_PKT_RTV(p) ((p)->root ? (p)->root->tunnel_rtv_cnt : (p)->tunnel_rtv_cnt)
#define TUNNEL_PKT_TPR(p) ((p)->root ? (p)->root->tunnel_tpr_cnt : (p)->tunnel_tpr_cnt)

#define IS_TUNNEL_PKT(p)            (((p)->flags & PKT_TUNNEL))
#define SET_TUNNEL_PKT(p)           ((p)->flags |= PKT_TUNNEL)
#define UNSET_TUNNEL_PKT(p)         ((p)->flags &= ~PKT_TUNNEL)
#define IS_TUNNEL_ROOT_PKT(p)       (IS_TUNNEL_PKT(p) && (p)->root == NULL)

#define IS_TUNNEL_PKT_VERDICTED(p)  (((p)->flags & PKT_TUNNEL_VERDICTED))
#define SET_TUNNEL_PKT_VERDICTED(p) ((p)->flags |= PKT_TUNNEL_VERDICTED)

enum DecodeTunnelProto {
    DECODE_TUNNEL_ETHERNET,
    DECODE_TUNNEL_ERSPAN,
    DECODE_TUNNEL_VLAN,
    DECODE_TUNNEL_IPV4,
    DECODE_TUNNEL_IPV6,
    DECODE_TUNNEL_PPP,
};

Packet *PacketTunnelPktSetup(ThreadVars *tv, DecodeThreadVars *dtv, Packet *parent,
                             uint8_t *pkt, uint32_t len, enum DecodeTunnelProto proto, PacketQueue *pq);
Packet *PacketDefragPktSetup(Packet *parent, uint8_t *pkt, uint32_t len, uint8_t proto);
void PacketDefragPktSetupParent(Packet *parent);
void DecodeRegisterPerfCounters(DecodeThreadVars *, ThreadVars *);
Packet *PacketGetFromQueueOrAlloc(void);
Packet *PacketGetFromAlloc(void);
void PacketDecodeFinalize(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p);
void PacketUpdateEngineEventCounters(ThreadVars *tv,
        DecodeThreadVars *dtv, Packet *p);
void PacketFree(Packet *p);
void PacketFreeOrRelease(Packet *p);
int PacketCallocExtPkt(Packet *p, int datalen);
int PacketCopyData(Packet *p, uint8_t *pktdata, uint32_t pktlen);
int PacketSetData(Packet *p, uint8_t *pktdata, uint32_t pktlen);
int PacketCopyDataOffset(Packet *p, uint32_t offset, uint8_t *data, uint32_t datalen);
const char *PktSrcToString(enum PktSrcEnum pkt_src);
void PacketBypassCallback(Packet *p);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -905,6 +905,7 @@
     DECODE_TUNNEL_VLAN,
     DECODE_TUNNEL_IPV4,
     DECODE_TUNNEL_IPV6,
+    DECODE_TUNNEL_IPV6_TEREDO,  /**< separate protocol for stricter error handling */
     DECODE_TUNNEL_PPP,
 };
 
```
