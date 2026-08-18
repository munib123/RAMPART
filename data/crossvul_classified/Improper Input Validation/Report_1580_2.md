# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1580_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1580_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 727-767 of the vulnerable file.


#else

void ParaNdis_DebugHistory(
    PARANDIS_ADAPTER *pContext,
    eHistoryLogOperation op,
    PVOID pParam1,
    ULONG lParam2,
    ULONG lParam3,
    ULONG lParam4);

#endif

void ParaNdis_ResetOffloadSettings(PARANDIS_ADAPTER *pContext, tOffloadSettingsFlags *pDest, PULONG from);

tChecksumCheckResult ParaNdis_CheckRxChecksum(
                                            PARANDIS_ADAPTER *pContext,
                                            ULONG virtioFlags,
                                            tCompletePhysicalAddress *pPacketPages,
                                            ULONG ulPacketLength,
                                            ULONG ulDataOffset);

void ParaNdis_CallOnBugCheck(PARANDIS_ADAPTER *pContext);

/*****************************************************
Procedures to implement for NDIS specific implementation
******************************************************/

PVOID ParaNdis_AllocateMemory(
    PARANDIS_ADAPTER *pContext,
    ULONG ulRequiredSize);

PVOID ParaNdis_AllocateMemoryRaw(
    NDIS_HANDLE MiniportHandle,
    ULONG ulRequiredSize);

NDIS_STATUS ParaNdis_FinishSpecificInitialization(
    PARANDIS_ADAPTER *pContext);

VOID ParaNdis_FinalizeCleanup(
    PARANDIS_ADAPTER *pContext);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -744,7 +744,8 @@
                                             ULONG virtioFlags,
                                             tCompletePhysicalAddress *pPacketPages,
                                             ULONG ulPacketLength,
-                                            ULONG ulDataOffset);
+                                            ULONG ulDataOffset,
+                                            BOOLEAN verifyLength);
 
 void ParaNdis_CallOnBugCheck(PARANDIS_ADAPTER *pContext);
 
@@ -917,6 +918,7 @@
                                                 ULONG ulDataLength,
                                                 ULONG ulStartOffset,
                                                 ULONG flags,
+                                                BOOLEAN verifyLength,
                                                 LPCSTR caller);
 
 static __inline
@@ -924,15 +926,16 @@
                                                 PVOID pBuffer,
                                                 ULONG ulDataLength,
                                                 ULONG flags,
+                                                BOOLEAN verifyLength,
                                                 LPCSTR caller)
 {
     tCompletePhysicalAddress SGBuffer;
     SGBuffer.Virtual = pBuffer;
     SGBuffer.size = ulDataLength;
-    return ParaNdis_CheckSumVerify(&SGBuffer, ulDataLength, 0, flags, caller);
+    return ParaNdis_CheckSumVerify(&SGBuffer, ulDataLength, 0, flags, verifyLength, caller);
 }
 
-tTcpIpPacketParsingResult ParaNdis_ReviewIPPacket(PVOID buffer, ULONG size, LPCSTR caller);
+tTcpIpPacketParsingResult ParaNdis_ReviewIPPacket(PVOID buffer, ULONG size, BOOLEAN verityLength, LPCSTR caller);
 
 BOOLEAN ParaNdis_AnalyzeReceivedPacket(PVOID headersBuffer, ULONG dataLength, PNET_PACKET_INFO packetInfo);
 ULONG ParaNdis_StripVlanHeaderMoveHead(PNET_PACKET_INFO packetInfo);
```
