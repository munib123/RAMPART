# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1580_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1580_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 849-889 of the vulnerable file.

            pNBL->SourceHandle = pContext->MiniportHandle;
            NBLSetRSSInfo(pContext, pNBL, pPacketInfo);
            NBLSet8021QInfo(pContext, pNBL, pPacketInfo);

            pNBL->MiniportReserved[0] = pBuffersDesc;

#if PARANDIS_SUPPORT_RSC
            if(pHeader->gso_type != VIRTIO_NET_HDR_GSO_NONE)
            {
                *pnCoalescedSegmentsCount = PktGetTCPCoalescedSegmentsCount(pPacketInfo, pContext->MaxPacketSize.nMaxDataSize);
                NBLSetRSCInfo(pContext, pNBL, pPacketInfo, *pnCoalescedSegmentsCount);
            }
            else
#endif
            {
                csRes = ParaNdis_CheckRxChecksum(
                    pContext,
                    pHeader->flags,
                    &pBuffersDesc->PhysicalPages[PARANDIS_FIRST_RX_DATA_PAGE],
                    pPacketInfo->dataLength,
                    nBytesStripped);
                if (csRes.value)
                {
                    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO qCSInfo;
                    qCSInfo.Value = NULL;
                    qCSInfo.Receive.IpChecksumFailed = csRes.flags.IpFailed;
                    qCSInfo.Receive.IpChecksumSucceeded = csRes.flags.IpOK;
                    qCSInfo.Receive.TcpChecksumFailed = csRes.flags.TcpFailed;
                    qCSInfo.Receive.TcpChecksumSucceeded = csRes.flags.TcpOK;
                    qCSInfo.Receive.UdpChecksumFailed = csRes.flags.UdpFailed;
                    qCSInfo.Receive.UdpChecksumSucceeded = csRes.flags.UdpOK;
                    NET_BUFFER_LIST_INFO(pNBL, TcpIpChecksumNetBufferListInfo) = qCSInfo.Value;
                    DPrintf(1, ("Reporting CS %X->%X\n", csRes.value, (ULONG)(ULONG_PTR)qCSInfo.Value));
                }
            }
            pNBL->Status = NDIS_STATUS_SUCCESS;
#if defined(ENABLE_HISTORY_LOG)
            {
                tTcpIpPacketParsingResult packetReview = ParaNdis_CheckSumVerify(
                    RtlOffsetToPointer(pPacketInfo->headersBuffer, ETH_HEADER_SIZE),
                    pPacketInfo->dataLength,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -866,7 +866,7 @@
                     pHeader->flags,
                     &pBuffersDesc->PhysicalPages[PARANDIS_FIRST_RX_DATA_PAGE],
                     pPacketInfo->dataLength,
-                    nBytesStripped);
+                    nBytesStripped, TRUE);
                 if (csRes.value)
                 {
                     NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO qCSInfo;
```
