# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1581_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1581_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 139-179 of the vulnerable file.


    return RawCheckSumFinalize(u32RawCSum);
}


/******************************************
    IP header checksum calculator
*******************************************/
static __inline VOID CalculateIpChecksum(IPv4Header *pIpHeader)
{
    pIpHeader->ip_xsum = 0;
    pIpHeader->ip_xsum = CheckSumCalculatorFlat(pIpHeader, IP_HEADER_LENGTH(pIpHeader));
}

static __inline tTcpIpPacketParsingResult
ProcessTCPHeader(tTcpIpPacketParsingResult _res, PVOID pIpHeader, ULONG len, USHORT ipHeaderSize)
{
    ULONG tcpipDataAt;
    tTcpIpPacketParsingResult res = _res;
    tcpipDataAt = ipHeaderSize + sizeof(TCPHeader);
    res.xxpStatus = ppresXxpIncomplete;
    res.TcpUdp = ppresIsTCP;

    if (len >= tcpipDataAt)
    {
        TCPHeader *pTcpHeader = (TCPHeader *)RtlOffsetToPointer(pIpHeader, ipHeaderSize);
        res.xxpStatus = ppresXxpKnown;
        tcpipDataAt = ipHeaderSize + TCP_HEADER_LENGTH(pTcpHeader);
        res.XxpIpHeaderSize = tcpipDataAt;
    }
    else
    {
        DPrintf(2, ("tcp: %d < min headers %d\n", len, tcpipDataAt));
    }
    return res;
}

static __inline tTcpIpPacketParsingResult
ProcessUDPHeader(tTcpIpPacketParsingResult _res, PVOID pIpHeader, ULONG len, USHORT ipHeaderSize)
{
    tTcpIpPacketParsingResult res = _res;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,19 +156,21 @@
     ULONG tcpipDataAt;
     tTcpIpPacketParsingResult res = _res;
     tcpipDataAt = ipHeaderSize + sizeof(TCPHeader);
-    res.xxpStatus = ppresXxpIncomplete;
     res.TcpUdp = ppresIsTCP;
 
     if (len >= tcpipDataAt)
     {
         TCPHeader *pTcpHeader = (TCPHeader *)RtlOffsetToPointer(pIpHeader, ipHeaderSize);
         res.xxpStatus = ppresXxpKnown;
+        res.xxpFull = TRUE;
         tcpipDataAt = ipHeaderSize + TCP_HEADER_LENGTH(pTcpHeader);
         res.XxpIpHeaderSize = tcpipDataAt;
     }
     else
     {
         DPrintf(2, ("tcp: %d < min headers %d\n", len, tcpipDataAt));
+        res.xxpFull = FALSE;
+        res.xxpStatus = ppresXxpIncomplete;
     }
     return res;
 }
@@ -178,7 +180,6 @@
 {
     tTcpIpPacketParsingResult res = _res;
     ULONG udpDataStart = ipHeaderSize + sizeof(UDPHeader);
-    res.xxpStatus = ppresXxpIncomplete;
     res.TcpUdp = ppresIsUDP;
     res.XxpIpHeaderSize = udpDataStart;
     if (len >= udpDataStart)
@@ -186,9 +187,15 @@
         UDPHeader *pUdpHeader = (UDPHeader *)RtlOffsetToPointer(pIpHeader, ipHeaderSize);
         USHORT datagramLength = swap_short(pUdpHeader->udp_length);
         res.xxpStatus = ppresXxpKnown;
+        res.xxpFull = TRUE;
         // may be full or not, but the datagram length is known
         DPrintf(2, ("udp: len %d, datagramLength %d\n", len, datagramLength));
     }
+    else
+    {
+        res.xxpFull = FALSE;
+        res.xxpStatus = ppresXxpIncomplete;
+    }
     return res;
 }
 
@@ -196,24 +203,44 @@
 QualifyIpPacket(IPHeader *pIpHeader, ULONG len)
 {
     tTcpIpPacketParsingResult res;
+    res.value = 0;
+
+    if (len < 4)
+    {
+        res.ipStatus = ppresNotIP;
+        return res;
+    }
+
     UCHAR  ver_len = pIpHeader->v4.ip_verlen;
     UCHAR  ip_version = (ver_len & 0xF0) >> 4;
     USHORT ipHeaderSize = 0;
     USHORT fullLength = 0;
     res.value = 0;
-    
+
     if (ip_version == 4)
     {
+        if (len < sizeof(IPv4Header))
+        {
+            res.ipStatus = ppresNotIP;
+            return res;
+        }
         ipHeaderSize = (ver_len & 0xF) << 2;
         fullLength = swap_short(pIpHeader->v4.ip_length);
-        DPrintf(3, ("ip_version %d, ipHeaderSize %d, protocol %d, iplen %d\n",
-            ip_version, ipHeaderSize, pIpHeader->v4.ip_protocol, fullLength));
+        DPrintf(3, ("ip_version %d, ipHeaderSize %d, protocol %d, iplen %d, L2 payload length %d\n",
+            ip_version, ipHeaderSize, pIpHeader->v4.ip_protocol, fullLength, len));
+
         res.ipStatus = (ipHeaderSize >= sizeof(IPv4Header)) ? ppresIPV4 : ppresNotIP;
-        if (len < ipHeaderSize) res.ipCheckSum = ppresIPTooShort;
-        if (fullLength) {}
-        else
-        {
-            DPrintf(2, ("ip v.%d, iplen %d\n", ip_version, fullLength));
+        if (res.ipStatus == ppresNotIP)
+        {
+            return res;
+        }
+
+        if (ipHeaderSize >= fullLength || len < fullLength)
+        {
+            DPrintf(2, ("[%s] - truncated packet - ip_version %d, ipHeaderSize %d, protocol %d, iplen %d, L2 payload length %d\n",
+                ip_version, ipHeaderSize, pIpHeader->v4.ip_protocol, fullLength, len));
+            res.ipCheckSum = ppresIPTooShort;
+            return res;
         }
     }
     else if (ip_version == 6)
@@ -291,7 +318,7 @@
     if (res.ipStatus == ppresIPV4)
     {
         res.ipHeaderSize = ipHeaderSize;
-        res.xxpFull = len >= fullLength ? 1 : 0;
+
         // bit "more fragments" or fragment offset mean the packet is fragmented
         res.IsFragment = (pIpHeader->v4.ip_offset & ~0xC0) != 0;
         switch (pIpHeader->v4.ip_protocol)
@@ -615,6 +642,9 @@
     IPHeader *pIpHeader = (IPHeader *) RtlOffsetToPointer(pDataPages[0].Virtual, ulStartOffset);
 
     tTcpIpPacketParsingResult res = QualifyIpPacket(pIpHeader, ulDataLength);
+    if (res.ipStatus == ppresNotIP || res.ipCheckSum == ppresIPTooShort)
+        return res;
+
     if (res.ipStatus == ppresIPV4)
     {
         if (flags & pcrIpChecksum)
```
