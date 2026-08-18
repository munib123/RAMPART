# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3910_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3910_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 85-125 of the vulnerable file.

	"Set Error Info",               /* 0x2F */
	"Draw Nine Grid Error",         /* 0x30 */
	"Draw GDI+ Error",              /* 0x31 */
	"ARC Status",                   /* 0x32 */
	"?",
	"?",
	"?",              /* 0x33 - 0x35 */
	"Status Info",    /* 0x36 */
	"Monitor Layout", /* 0x37 */
	"FrameAcknowledge",
	"?",
	"?", /* 0x38 - 0x40 */
	"?",
	"?",
	"?",
	"?",
	"?",
	"?" /* 0x41 - 0x46 */
};

static void rdp_read_flow_control_pdu(wStream* s, UINT16* type);
static void rdp_write_share_control_header(wStream* s, UINT16 length, UINT16 type,
                                           UINT16 channel_id);
static void rdp_write_share_data_header(wStream* s, UINT16 length, BYTE type, UINT32 share_id);

/**
 * Read RDP Security Header.\n
 * @msdn{cc240579}
 * @param s stream
 * @param flags security flags
 */

BOOL rdp_read_security_header(wStream* s, UINT16* flags, UINT16* length)
{
	/* Basic Security Header */
	if ((Stream_GetRemainingLength(s) < 4) || (length && (*length < 4)))
		return FALSE;

	Stream_Read_UINT16(s, *flags); /* flags */
	Stream_Seek(s, 2);             /* flagsHi (unused) */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,7 +102,7 @@
 	"?" /* 0x41 - 0x46 */
 };
 
-static void rdp_read_flow_control_pdu(wStream* s, UINT16* type);
+static BOOL rdp_read_flow_control_pdu(wStream* s, UINT16* type);
 static void rdp_write_share_control_header(wStream* s, UINT16 length, UINT16 type,
                                            UINT16 channel_id);
 static void rdp_write_share_data_header(wStream* s, UINT16 length, BYTE type, UINT32 share_id);
@@ -145,29 +145,33 @@
 
 BOOL rdp_read_share_control_header(wStream* s, UINT16* length, UINT16* type, UINT16* channel_id)
 {
+	UINT16 len;
 	if (Stream_GetRemainingLength(s) < 2)
 		return FALSE;
 
 	/* Share Control Header */
-	Stream_Read_UINT16(s, *length); /* totalLength */
+	Stream_Read_UINT16(s, len); /* totalLength */
+
+	*length = len;
 
 	/* If length is 0x8000 then we actually got a flow control PDU that we should ignore
 	 http://msdn.microsoft.com/en-us/library/cc240576.aspx */
-	if (*length == 0x8000)
-	{
-		rdp_read_flow_control_pdu(s, type);
+	if (len == 0x8000)
+	{
+		if (!rdp_read_flow_control_pdu(s, type))
+			return FALSE;
 		*channel_id = 0;
 		*length = 8; /* Flow control PDU is 8 bytes */
 		return TRUE;
 	}
 
-	if (((size_t)*length - 2) > Stream_GetRemainingLength(s))
+	if ((len < 4) || ((len - 2) > Stream_GetRemainingLength(s)))
 		return FALSE;
 
 	Stream_Read_UINT16(s, *type); /* pduType */
 	*type &= 0x0F;                /* type is in the 4 least significant bits */
 
-	if (*length > 4)
+	if (len > 4)
 		Stream_Read_UINT16(s, *channel_id); /* pduSource */
 	else
 		*channel_id = 0; /* Windows XP can send such short DEACTIVATE_ALL PDUs. */
@@ -1116,7 +1120,7 @@
 	}
 }
 
-void rdp_read_flow_control_pdu(wStream* s, UINT16* type)
+BOOL rdp_read_flow_control_pdu(wStream* s, UINT16* type)
 {
 	/*
 	 * Read flow control PDU - documented in FlowPDU section in T.128
@@ -1126,12 +1130,17 @@
 	 * Switched the order of these two fields to match this observation.
 	 */
 	UINT8 pduType;
+	if (!type)
+		return FALSE;
+	if (Stream_GetRemainingLength(s) < 6)
+		return FALSE;
 	Stream_Read_UINT8(s, pduType); /* pduTypeFlow */
 	*type = pduType;
 	Stream_Seek_UINT8(s);  /* pad8bits */
 	Stream_Seek_UINT8(s);  /* flowIdentifier */
 	Stream_Seek_UINT8(s);  /* flowNumber */
 	Stream_Seek_UINT16(s); /* pduSource */
+	return TRUE;
 }
 
 /**
```
