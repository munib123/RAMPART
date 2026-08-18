# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3911_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3911_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 448-488 of the vulnerable file.

		rdp->autodetect->bandwidthMeasureStarted = FALSE;
	}

	/* Send a response the server */
	responseType = autodetectReqPdu->requestType == RDP_BW_STOP_REQUEST_TYPE_CONNECTTIME
	                   ? RDP_BW_RESULTS_RESPONSE_TYPE_CONNECTTIME
	                   : RDP_BW_RESULTS_RESPONSE_TYPE_CONTINUOUS;
	return autodetect_send_bandwidth_measure_results(rdp, responseType,
	                                                 autodetectReqPdu->sequenceNumber);
}

static BOOL autodetect_recv_bandwidth_measure_results(rdpRdp* rdp, wStream* s,
                                                      AUTODETECT_RSP_PDU* autodetectRspPdu)
{
	BOOL success = TRUE;

	if (autodetectRspPdu->headerLength != 0x0E)
		return FALSE;

	WLog_VRB(AUTODETECT_TAG, "received Bandwidth Measure Results PDU");
	Stream_Read_UINT32(s, rdp->autodetect->bandwidthMeasureTimeDelta); /* timeDelta (4 bytes) */
	Stream_Read_UINT32(s, rdp->autodetect->bandwidthMeasureByteCount); /* byteCount (4 bytes) */

	if (rdp->autodetect->bandwidthMeasureTimeDelta > 0)
		rdp->autodetect->netCharBandwidth = rdp->autodetect->bandwidthMeasureByteCount * 8 /
		                                    rdp->autodetect->bandwidthMeasureTimeDelta;
	else
		rdp->autodetect->netCharBandwidth = 0;

	IFCALLRET(rdp->autodetect->BandwidthMeasureResults, success, rdp->context,
	          autodetectRspPdu->sequenceNumber);
	return success;
}

static BOOL autodetect_recv_netchar_result(rdpRdp* rdp, wStream* s,
                                           AUTODETECT_REQ_PDU* autodetectReqPdu)
{
	BOOL success = TRUE;

	switch (autodetectReqPdu->requestType)
	{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -465,6 +465,8 @@
 		return FALSE;
 
 	WLog_VRB(AUTODETECT_TAG, "received Bandwidth Measure Results PDU");
+	if (Stream_GetRemainingLength(s) < 8)
+		return -1;
 	Stream_Read_UINT32(s, rdp->autodetect->bandwidthMeasureTimeDelta); /* timeDelta (4 bytes) */
 	Stream_Read_UINT32(s, rdp->autodetect->bandwidthMeasureByteCount); /* byteCount (4 bytes) */
 
```
