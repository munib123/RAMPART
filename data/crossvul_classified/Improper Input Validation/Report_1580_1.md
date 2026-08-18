# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1580_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1580_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 632-672 of the vulnerable file.

                                        NDIS_SG_LIST_WRITE_TO_DEVICE, nullptr, 0) == NDIS_STATUS_SUCCESS;
}

void CNB::PopulateIPLength(IPv4Header *IpHeader, USHORT IpLength) const
{
    if ((IpHeader->ip_verlen & 0xF0) == 0x40)
    {
        if (!IpHeader->ip_length) {
            IpHeader->ip_length = swap_short(IpLength);
        }
    }
}

void CNB::SetupLSO(virtio_net_hdr_basic *VirtioHeader, PVOID IpHeader, ULONG EthPayloadLength) const
{
    PopulateIPLength(reinterpret_cast<IPv4Header*>(IpHeader), static_cast<USHORT>(EthPayloadLength));

    tTcpIpPacketParsingResult packetReview;
    packetReview = ParaNdis_CheckSumVerifyFlat(reinterpret_cast<IPv4Header*>(IpHeader), EthPayloadLength,
                                               pcrIpChecksum | pcrFixIPChecksum | pcrTcpChecksum | pcrFixPHChecksum,
                                               __FUNCTION__);

    if (packetReview.xxpCheckSum == ppresPCSOK || packetReview.fixedXxpCS)
    {
        auto IpHeaderOffset = m_Context->Offload.ipHeaderOffset;
        auto VHeader = static_cast<virtio_net_hdr_basic*>(VirtioHeader);
        auto PriorityHdrLen = (m_ParentNBL->TCI() != 0) ? ETH_PRIORITY_HEADER_SIZE : 0;

        VHeader->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        VHeader->gso_type = packetReview.ipStatus == ppresIPV4 ? VIRTIO_NET_HDR_GSO_TCPV4 : VIRTIO_NET_HDR_GSO_TCPV6;
        VHeader->hdr_len = (USHORT)(packetReview.XxpIpHeaderSize + IpHeaderOffset + PriorityHdrLen);
        VHeader->gso_size = (USHORT)m_ParentNBL->MSS();
        VHeader->csum_start = (USHORT)(m_ParentNBL->TCPHeaderOffset() + PriorityHdrLen);
        VHeader->csum_offset = TCP_CHECKSUM_OFFSET;
    }
}

USHORT CNB::QueryL4HeaderOffset(PVOID PacketData, ULONG IpHeaderOffset) const
{
    USHORT Res;
    auto ppr = ParaNdis_ReviewIPPacket(RtlOffsetToPointer(PacketData, IpHeaderOffset),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -649,6 +649,7 @@
     tTcpIpPacketParsingResult packetReview;
     packetReview = ParaNdis_CheckSumVerifyFlat(reinterpret_cast<IPv4Header*>(IpHeader), EthPayloadLength,
                                                pcrIpChecksum | pcrFixIPChecksum | pcrTcpChecksum | pcrFixPHChecksum,
+                                               FALSE,
                                                __FUNCTION__);
 
     if (packetReview.xxpCheckSum == ppresPCSOK || packetReview.fixedXxpCS)
@@ -670,7 +671,7 @@
 {
     USHORT Res;
     auto ppr = ParaNdis_ReviewIPPacket(RtlOffsetToPointer(PacketData, IpHeaderOffset),
-                                       GetDataLength(), __FUNCTION__);
+                                       GetDataLength(), FALSE, __FUNCTION__);
     if (ppr.ipStatus != ppresNotIP)
     {
         Res = static_cast<USHORT>(IpHeaderOffset + ppr.ipHeaderSize);
@@ -696,7 +697,7 @@
 {
     ParaNdis_CheckSumVerifyFlat(IpHeader,
                                 EthPayloadLength,
-                                pcrIpChecksum | pcrFixIPChecksum,
+                                pcrIpChecksum | pcrFixIPChecksum, FALSE,
                                 __FUNCTION__);
 }
 
```
