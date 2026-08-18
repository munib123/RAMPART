# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3946_4
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3946_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 287-327 of the vulnerable file.

static wStream* rdg_receive_packet(rdpRdg* rdg)
{
	wStream* s;
	const size_t header = sizeof(RdgPacketHeader);
	size_t packetLength;
	assert(header <= INT_MAX);
	s = Stream_New(NULL, 1024);

	if (!s)
		return NULL;

	if (!rdg_read_all(rdg->tlsOut, Stream_Buffer(s), header))
	{
		Stream_Free(s, TRUE);
		return NULL;
	}

	Stream_Seek(s, 4);
	Stream_Read_UINT32(s, packetLength);

	if ((packetLength > INT_MAX) || !Stream_EnsureCapacity(s, packetLength))
	{
		Stream_Free(s, TRUE);
		return NULL;
	}

	if (!rdg_read_all(rdg->tlsOut, Stream_Buffer(s) + header, (int)packetLength - (int)header))
	{
		Stream_Free(s, TRUE);
		return NULL;
	}

	Stream_SetLength(s, packetLength);
	return s;
}

static BOOL rdg_send_handshake(rdpRdg* rdg)
{
	wStream* s;
	BOOL status;
	s = Stream_New(NULL, 14);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -304,7 +304,8 @@
 	Stream_Seek(s, 4);
 	Stream_Read_UINT32(s, packetLength);
 
-	if ((packetLength > INT_MAX) || !Stream_EnsureCapacity(s, packetLength))
+	if ((packetLength > INT_MAX) || !Stream_EnsureCapacity(s, packetLength) ||
+	    (packetLength < header))
 	{
 		Stream_Free(s, TRUE);
 		return NULL;
```
