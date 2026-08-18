# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1580_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1580_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 183-223 of the vulnerable file.

    res.TcpUdp = ppresIsUDP;
    res.XxpIpHeaderSize = udpDataStart;
    if (len >= udpDataStart)
    {
        UDPHeader *pUdpHeader = (UDPHeader *)RtlOffsetToPointer(pIpHeader, ipHeaderSize);
        USHORT datagramLength = swap_short(pUdpHeader->udp_length);
        res.xxpStatus = ppresXxpKnown;
        res.xxpFull = TRUE;
        // may be full or not, but the datagram length is known
        DPrintf(2, ("udp: len %d, datagramLength %d\n", len, datagramLength));
    }
    else
    {
        res.xxpFull = FALSE;
        res.xxpStatus = ppresXxpIncomplete;
    }
    return res;
}

static __inline tTcpIpPacketParsingResult
QualifyIpPacket(IPHeader *pIpHeader, ULONG len)
{
    tTcpIpPacketParsingResult res;
    res.value = 0;

    if (len < 4)
    {
        res.ipStatus = ppresNotIP;
        return res;
    }

    UCHAR  ver_len = pIpHeader->v4.ip_verlen;
    UCHAR  ip_version = (ver_len & 0xF0) >> 4;
    USHORT ipHeaderSize = 0;
    USHORT fullLength = 0;
    res.value = 0;

    if (ip_version == 4)
    {
        if (len < sizeof(IPv4Header))
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -200,7 +200,7 @@
 }
 
 static __inline tTcpIpPacketParsingResult
-QualifyIpPacket(IPHeader *pIpHeader, ULONG len)
+QualifyIpPacket(IPHeader *pIpHeader, ULONG len, BOOLEAN verifyLength)
 {
     tTcpIpPacketParsingResult res;
     res.value = 0;
@@ -235,10 +235,10 @@
             return res;
         }
 
-        if (ipHeaderSize >= fullLength || len < fullLength)
-        {
-            DPrintf(2, ("[%s] - truncated packet - ip_version %d, ipHeaderSize %d, protocol %d, iplen %d, L2 payload length %d\n", __FUNCTION__,
-                ip_version, ipHeaderSize, pIpHeader->v4.ip_protocol, fullLength, len));
+        if (ipHeaderSize >= fullLength || ( verifyLength && len < fullLength))
+        {
+            DPrintf(2, ("[%s] - truncated packet - ip_version %d, ipHeaderSize %d, protocol %d, iplen %d, L2 payload length %d, verify = %s\n", __FUNCTION__,
+                ip_version, ipHeaderSize, pIpHeader->v4.ip_protocol, fullLength, len, (verifyLength ? "true" : "false")));
             res.ipCheckSum = ppresIPTooShort;
             return res;
         }
@@ -258,7 +258,8 @@
         res.ipCheckSum = ppresCSOK;
         fullLength = swap_short(pIpHeader->v6.ip6_payload_len);
         fullLength += ipHeaderSize;
-        if (len < fullLength)
+
+        if (verifyLength && (len < fullLength))
         {
             res.ipStatus = ppresNotIP;
             return res;
@@ -648,11 +649,12 @@
                                                 ULONG ulDataLength,
                                                 ULONG ulStartOffset,
                                                 ULONG flags,
+                                                BOOLEAN verifyLength,
                                                 LPCSTR caller)
 {
     IPHeader *pIpHeader = (IPHeader *) RtlOffsetToPointer(pDataPages[0].Virtual, ulStartOffset);
 
-    tTcpIpPacketParsingResult res = QualifyIpPacket(pIpHeader, ulDataLength);
+    tTcpIpPacketParsingResult res = QualifyIpPacket(pIpHeader, ulDataLength, verifyLength);
     if (res.ipStatus == ppresNotIP || res.ipCheckSum == ppresIPTooShort)
         return res;
 
@@ -702,9 +704,9 @@
     return res;
 }
 
-tTcpIpPacketParsingResult ParaNdis_ReviewIPPacket(PVOID buffer, ULONG size, LPCSTR caller)
-{
-    tTcpIpPacketParsingResult res = QualifyIpPacket((IPHeader *) buffer, size);
+tTcpIpPacketParsingResult ParaNdis_ReviewIPPacket(PVOID buffer, ULONG size, BOOLEAN verifyLength, LPCSTR caller)
+{
+    tTcpIpPacketParsingResult res = QualifyIpPacket((IPHeader *) buffer, size, verifyLength);
     PrintOutParsingResult(res, 1, caller);
     return res;
 }
```
