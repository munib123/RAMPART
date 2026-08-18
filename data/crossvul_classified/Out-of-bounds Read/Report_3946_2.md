# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3946_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3946_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 428-468 of the vulnerable file.

	RdpeiClientContext* rdpei = (RdpeiClientContext*)callback->plugin->pInterface;
	UINT error = CHANNEL_RC_OK;
	IFCALLRET(rdpei->ResumeTouch, error, rdpei);

	if (error)
		WLog_ERR(TAG, "rdpei->ResumeTouch failed with error %" PRIu32 "!", error);

	return error;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT rdpei_recv_pdu(RDPEI_CHANNEL_CALLBACK* callback, wStream* s)
{
	UINT16 eventId;
	UINT32 pduLength;
	UINT error;
	Stream_Read_UINT16(s, eventId);   /* eventId (2 bytes) */
	Stream_Read_UINT32(s, pduLength); /* pduLength (4 bytes) */
#ifdef WITH_DEBUG_RDPEI
	WLog_DBG(TAG, "rdpei_recv_pdu: eventId: %" PRIu16 " (%s) length: %" PRIu32 "", eventId,
	         rdpei_eventid_string(eventId), pduLength);
#endif

	switch (eventId)
	{
		case EVENTID_SC_READY:
			if ((error = rdpei_recv_sc_ready_pdu(callback, s)))
			{
				WLog_ERR(TAG, "rdpei_recv_sc_ready_pdu failed with error %" PRIu32 "!", error);
				return error;
			}

			if ((error = rdpei_send_cs_ready_pdu(callback)))
			{
				WLog_ERR(TAG, "rdpei_send_cs_ready_pdu failed with error %" PRIu32 "!", error);
				return error;
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -445,6 +445,9 @@
 	UINT16 eventId;
 	UINT32 pduLength;
 	UINT error;
+	if (Stream_GetRemainingLength(s) < 6)
+		return ERROR_INVALID_DATA;
+
 	Stream_Read_UINT16(s, eventId);   /* eventId (2 bytes) */
 	Stream_Read_UINT32(s, pduLength); /* pduLength (4 bytes) */
 #ifdef WITH_DEBUG_RDPEI
```
