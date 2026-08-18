# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 486_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `486_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 101-141 of the vulnerable file.

	uint8 buffer[4];

	logger(Clipboard, Debug, "cliprdr_send_data_request(), format 0x%x", format);
	buf_out_uint32(buffer, format);
	cliprdr_send_packet(CLIPRDR_DATA_REQUEST, CLIPRDR_REQUEST, buffer, sizeof(buffer));
}

void
cliprdr_send_data(uint8 * data, uint32 length)
{
	logger(Clipboard, Debug, "cliprdr_send_data(), length %d bytes", length);
	cliprdr_send_packet(CLIPRDR_DATA_RESPONSE, CLIPRDR_RESPONSE, data, length);
}

static void
cliprdr_process(STREAM s)
{
	uint16 type, status;
	uint32 length, format;
	uint8 *data;

	in_uint16_le(s, type);
	in_uint16_le(s, status);
	in_uint32_le(s, length);
	data = s->p;

	logger(Clipboard, Debug, "cliprdr_process(), type=%d, status=%d, length=%d", type, status,
	       length);

	if (status == CLIPRDR_ERROR)
	{
		switch (type)
		{
			case CLIPRDR_FORMAT_ACK:
				/* FIXME: We seem to get this when we send an announce while the server is
				   still processing a paste. Try sending another announce. */
				cliprdr_send_native_format_announce(last_formats,
								    last_formats_length);
				break;
			case CLIPRDR_DATA_RESPONSE:
				ui_clip_request_failed();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -118,6 +118,7 @@
 	uint16 type, status;
 	uint32 length, format;
 	uint8 *data;
+	struct stream packet = *s;
 
 	in_uint16_le(s, type);
 	in_uint16_le(s, status);
@@ -126,6 +127,11 @@
 
 	logger(Clipboard, Debug, "cliprdr_process(), type=%d, status=%d, length=%d", type, status,
 	       length);
+
+	if (!s_check_rem(s, length))
+	{
+		rdp_protocol_error("cliprdr_process(), consume of packet from stream would overrun", &packet);
+	}
 
 	if (status == CLIPRDR_ERROR)
 	{
```
