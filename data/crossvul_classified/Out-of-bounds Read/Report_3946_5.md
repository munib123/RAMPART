# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3946_5
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3946_5`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 74-116 of the vulnerable file.

	if (state >= ARRAYSIZE(NEGO_STATE_STRINGS))
		return NEGO_STATE_STRINGS[ARRAYSIZE(NEGO_STATE_STRINGS) - 1];
	return NEGO_STATE_STRINGS[state];
}

static const char* protocol_security_string(UINT32 security)
{
	static const char* PROTOCOL_SECURITY_STRINGS[] = { "RDP", "TLS", "NLA", "UNK", "UNK",
		                                               "UNK", "UNK", "UNK", "EXT", "UNK" };
	if (security >= ARRAYSIZE(PROTOCOL_SECURITY_STRINGS))
		return PROTOCOL_SECURITY_STRINGS[ARRAYSIZE(PROTOCOL_SECURITY_STRINGS) - 1];
	return PROTOCOL_SECURITY_STRINGS[security];
}

static BOOL nego_transport_connect(rdpNego* nego);
static BOOL nego_transport_disconnect(rdpNego* nego);
static BOOL nego_security_connect(rdpNego* nego);
static BOOL nego_send_preconnection_pdu(rdpNego* nego);
static BOOL nego_recv_response(rdpNego* nego);
static void nego_send(rdpNego* nego);
static void nego_process_negotiation_request(rdpNego* nego, wStream* s);
static void nego_process_negotiation_response(rdpNego* nego, wStream* s);
static void nego_process_negotiation_failure(rdpNego* nego, wStream* s);

/**
 * Negotiate protocol security and connect.
 * @param nego
 * @return
 */

BOOL nego_connect(rdpNego* nego)
{
	rdpSettings* settings = nego->transport->settings;

	if (nego->state == NEGO_STATE_INITIAL)
	{
		if (nego->EnabledProtocols[PROTOCOL_HYBRID_EX])
		{
			nego->state = NEGO_STATE_EXT;
		}
		else if (nego->EnabledProtocols[PROTOCOL_HYBRID])
		{
			nego->state = NEGO_STATE_NLA;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,9 +91,9 @@
 static BOOL nego_send_preconnection_pdu(rdpNego* nego);
 static BOOL nego_recv_response(rdpNego* nego);
 static void nego_send(rdpNego* nego);
-static void nego_process_negotiation_request(rdpNego* nego, wStream* s);
-static void nego_process_negotiation_response(rdpNego* nego, wStream* s);
-static void nego_process_negotiation_failure(rdpNego* nego, wStream* s);
+static BOOL nego_process_negotiation_request(rdpNego* nego, wStream* s);
+static BOOL nego_process_negotiation_response(rdpNego* nego, wStream* s);
+static BOOL nego_process_negotiation_failure(rdpNego* nego, wStream* s);
 
 /**
  * Negotiate protocol security and connect.
@@ -618,7 +618,8 @@
 		switch (type)
 		{
 			case TYPE_RDP_NEG_RSP:
-				nego_process_negotiation_response(nego, s);
+				if (!nego_process_negotiation_response(nego, s))
+					return -1;
 				WLog_DBG(TAG, "selected_protocol: %" PRIu32 "", nego->SelectedProtocol);
 
 				/* enhanced security selected ? */
@@ -645,7 +646,8 @@
 				break;
 
 			case TYPE_RDP_NEG_FAILURE:
-				nego_process_negotiation_failure(nego, s);
+				if (!nego_process_negotiation_failure(nego, s))
+					return -1;
 				break;
 		}
 	}
@@ -795,7 +797,8 @@
 			return FALSE;
 		}
 
-		nego_process_negotiation_request(nego, s);
+		if (!nego_process_negotiation_request(nego, s))
+			return FALSE;
 	}
 
 	return tpkt_ensure_stream_consumed(s, length);
@@ -918,15 +921,19 @@
  * @param s
  */
 
-void nego_process_negotiation_request(rdpNego* nego, wStream* s)
+BOOL nego_process_negotiation_request(rdpNego* nego, wStream* s)
 {
 	BYTE flags;
 	UINT16 length;
+
+	if (Stream_GetRemainingLength(s) < 7)
+		return FALSE;
 	Stream_Read_UINT8(s, flags);
 	Stream_Read_UINT16(s, length);
 	Stream_Read_UINT32(s, nego->RequestedProtocols);
 	WLog_DBG(TAG, "RDP_NEG_REQ: RequestedProtocol: 0x%08" PRIX32 "", nego->RequestedProtocols);
 	nego->state = NEGO_STATE_FINAL;
+	return TRUE;
 }
 
 /**
@@ -935,7 +942,7 @@
  * @param s
  */
 
-void nego_process_negotiation_response(rdpNego* nego, wStream* s)
+BOOL nego_process_negotiation_response(rdpNego* nego, wStream* s)
 {
 	UINT16 length;
 	WLog_DBG(TAG, "RDP_NEG_RSP");
@@ -944,13 +951,14 @@
 	{
 		WLog_ERR(TAG, "Invalid RDP_NEG_RSP");
 		nego->state = NEGO_STATE_FAIL;
-		return;
+		return FALSE;
 	}
 
 	Stream_Read_UINT8(s, nego->flags);
 	Stream_Read_UINT16(s, length);
 	Stream_Read_UINT32(s, nego->SelectedProtocol);
 	nego->state = NEGO_STATE_FINAL;
+	return TRUE;
 }
 
 /**
@@ -959,12 +967,14 @@
  * @param s
  */
 
-void nego_process_negotiation_failure(rdpNego* nego, wStream* s)
+BOOL nego_process_negotiation_failure(rdpNego* nego, wStream* s)
 {
 	BYTE flags;
 	UINT16 length;
 	UINT32 failureCode;
 	WLog_DBG(TAG, "RDP_NEG_FAILURE");
+	if (Stream_GetRemainingLength(s) < 7)
+		return FALSE;
 	Stream_Read_UINT8(s, flags);
 	Stream_Read_UINT16(s, length);
 	Stream_Read_UINT32(s, failureCode);
@@ -999,6 +1009,7 @@
 	}
 
 	nego->state = NEGO_STATE_FAIL;
+	return TRUE;
 }
 
 /**
```
