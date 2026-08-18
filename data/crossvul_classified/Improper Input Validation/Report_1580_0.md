# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1580_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1580_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 2202-2242 of the vulnerable file.


    ParaNdis_ResetVirtIONetDevice(pContext);
    ParaNdis_DebugHistory(pContext, hopPowerOff, NULL, 0, 0, 0);
}

void ParaNdis_CallOnBugCheck(PARANDIS_ADAPTER *pContext)
{
    if (pContext->AdapterResources.ulIOAddress)
    {
#ifdef DBG_USE_VIRTIO_PCI_ISR_FOR_HOST_REPORT
        WriteVirtIODeviceByte(pContext->IODevice->addr + VIRTIO_PCI_ISR, 1);
#endif
    }
}

tChecksumCheckResult ParaNdis_CheckRxChecksum(
                                            PARANDIS_ADAPTER *pContext,
                                            ULONG virtioFlags,
                                            tCompletePhysicalAddress *pPacketPages,
                                            ULONG ulPacketLength,
                                            ULONG ulDataOffset)
{
    tOffloadSettingsFlags f = pContext->Offload.flags;
    tChecksumCheckResult res;
    tTcpIpPacketParsingResult ppr;
    ULONG flagsToCalculate = 0;
    res.value = 0;

    //VIRTIO_NET_HDR_F_NEEDS_CSUM - we need to calculate TCP/UDP CS
    //VIRTIO_NET_HDR_F_DATA_VALID - host tells us TCP/UDP CS is OK

    if (f.fRxIPChecksum) flagsToCalculate |= pcrIpChecksum; // check only

    if (!(virtioFlags & VIRTIO_NET_HDR_F_DATA_VALID))
    {
        if (virtioFlags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
        {
            flagsToCalculate |= pcrFixXxpChecksum | pcrTcpChecksum | pcrUdpChecksum;
        }
        else
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2219,7 +2219,8 @@
                                             ULONG virtioFlags,
                                             tCompletePhysicalAddress *pPacketPages,
                                             ULONG ulPacketLength,
-                                            ULONG ulDataOffset)
+                                            ULONG ulDataOffset,
+                                            BOOLEAN verifyLength)
 {
     tOffloadSettingsFlags f = pContext->Offload.flags;
     tChecksumCheckResult res;
@@ -2247,7 +2248,8 @@
         }
     }
 
-    ppr = ParaNdis_CheckSumVerify(pPacketPages, ulPacketLength - ETH_HEADER_SIZE, ulDataOffset + ETH_HEADER_SIZE, flagsToCalculate, __FUNCTION__);
+    ppr = ParaNdis_CheckSumVerify(pPacketPages, ulPacketLength - ETH_HEADER_SIZE, ulDataOffset + ETH_HEADER_SIZE, flagsToCalculate,
+        verifyLength, __FUNCTION__);
 
     if (ppr.ipCheckSum == ppresIPTooShort || ppr.xxpStatus == ppresXxpIncomplete)
     {
```
