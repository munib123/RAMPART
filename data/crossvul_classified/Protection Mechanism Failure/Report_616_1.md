# CrossVul Fix Pair: Protection Mechanism Failure in c
**Pair ID:** 616_1
**Vulnerability Class:** Protection Mechanism Failure
**CWE:** CWE-693
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `616_1`)

## Vulnerability Information & PoC

## Description
Protection Mechanism Failure - This weakness covers three distinct situations.

## Vulnerable Code
```c
Lines 4722-4762 of the vulnerable file.

        }
    }

    SCReturnInt(0);

error:
    /* make sure we don't leave packets in our pseudo queue */
    while (stt->pseudo_queue.len > 0) {
        Packet *np = PacketDequeue(&stt->pseudo_queue);
        if (np != NULL) {
            PacketEnqueue(pq, np);
        }
    }

    /* recalc the csum on the packet if it was modified */
    if (p->flags & PKT_STREAM_MODIFIED) {
        ReCalculateChecksum(p);
    }

    if (StreamTcpInlineDropInvalid()) {
        PACKET_DROP(p);
    }
    SCReturnInt(-1);
}

/**
 *  \brief  Function to validate the checksum of the received packet. If the
 *          checksum is invalid, packet will be dropped, as the end system will
 *          also drop the packet.
 *
 *  \param  p       Packet of which checksum has to be validated
 *  \retval  1 if the checksum is valid, otherwise 0
 */
static inline int StreamTcpValidateChecksum(Packet *p)
{
    int ret = 1;

    if (p->flags & PKT_IGNORE_CHECKSUM)
        return ret;

    if (p->level4_comp_csum == -1) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4739,6 +4739,10 @@
     }
 
     if (StreamTcpInlineDropInvalid()) {
+        /* disable payload inspection as we're dropping this packet
+         * anyway. Doesn't disable all detection, so we can still
+         * match on the stream event that was set. */
+        DecodeSetNoPayloadInspectionFlag(p);
         PACKET_DROP(p);
     }
     SCReturnInt(-1);
```
