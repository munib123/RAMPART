# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 4593_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4593_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 217-257 of the vulnerable file.

}

//-----------------------------------------------------------------------------
int64 CSteamNetworkConnectionBase::SNP_SendMessage( CSteamNetworkingMessage *pSendMessage, SteamNetworkingMicroseconds usecNow, bool *pbThinkImmediately )
{
	int cbData = (int)pSendMessage->m_cbSize;

	// Assume we won't want to wake up immediately
	if ( pbThinkImmediately )
		*pbThinkImmediately = false;

	// Check if we're full
	if ( m_senderState.PendingBytesTotal() + cbData > m_connectionConfig.m_SendBufferSize.Get() )
	{
		SpewWarningRateLimited( usecNow, "Connection already has %u bytes pending, cannot queue any more messages\n", m_senderState.PendingBytesTotal() );
		pSendMessage->Release();
		return -k_EResultLimitExceeded; 
	}

	// Check if they try to send a really large message
	if ( cbData > k_cbMaxUnreliableMsgSize && !( pSendMessage->m_nFlags & k_nSteamNetworkingSend_Reliable )  )
	{
		SpewWarningRateLimited( usecNow, "Trying to send a very large (%d bytes) unreliable message.  Sending as reliable instead.\n", cbData );
		pSendMessage->m_nFlags |= k_nSteamNetworkingSend_Reliable;
	}

	if ( pSendMessage->m_nFlags & k_nSteamNetworkingSend_NoDelay )
	{
		// FIXME - need to check how much data is currently pending, and return
		// k_EResultIgnored if we think it's going to be a while before this
		// packet goes on the wire.
	}

	// First, accumulate tokens, and also limit to reasonable burst
	// if we weren't already waiting to send
	SNP_ClampSendRate();
	SNP_TokenBucket_Accumulate( usecNow );

	// Assign a message number
	pSendMessage->m_nMessageNumber = ++m_senderState.m_nLastSentMsgNum;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -234,7 +234,7 @@
 	}
 
 	// Check if they try to send a really large message
-	if ( cbData > k_cbMaxUnreliableMsgSize && !( pSendMessage->m_nFlags & k_nSteamNetworkingSend_Reliable )  )
+	if ( cbData > k_cbMaxUnreliableMsgSizeSend && !( pSendMessage->m_nFlags & k_nSteamNetworkingSend_Reliable )  )
 	{
 		SpewWarningRateLimited( usecNow, "Trying to send a very large (%d bytes) unreliable message.  Sending as reliable instead.\n", cbData );
 		pSendMessage->m_nFlags |= k_nSteamNetworkingSend_Reliable;
@@ -577,11 +577,23 @@
 			// Decode size, locate segment data
 			//
 			READ_SEGMENT_DATA_SIZE( unreliable )
-			Assert( cbSegmentSize > 0 ); // !TEST! Bogus assert, zero byte messages are OK.  Remove after testing
-
-			// Receive the segment
-			bool bLastSegmentInMessage = ( nFrameType & 0x20 ) != 0;
-			SNP_ReceiveUnreliableSegment( nCurMsgNum, nOffset, pSegmentData, cbSegmentSize, bLastSegmentInMessage, usecNow );
+
+			// Check if offset+size indicates a message larger than what we support.  (Also,
+			// protect against malicious sender sending *extremely* large offset causing overflow.)
+			if ( (int64)nOffset + cbSegmentSize > k_cbMaxUnreliableMsgSizeRecv || cbSegmentSize > k_cbMaxUnreliableSegmentSizeRecv )
+			{
+
+				// Since this is unreliable data, we can just ignore the segment.
+				SpewWarningRateLimited( usecNow, "[%s] Ignoring unreliable segment with invalid offset %u size %d\n",
+					GetDescription(), nOffset, cbSegmentSize );
+			}
+			else
+			{
+
+				// Receive the segment
+				bool bLastSegmentInMessage = ( nFrameType & 0x20 ) != 0;
+				SNP_ReceiveUnreliableSegment( nCurMsgNum, nOffset, pSegmentData, cbSegmentSize, bLastSegmentInMessage, usecNow );
+			}
 		}
 		else if ( ( nFrameType & 0xe0 ) == 0x40 )
 		{
```
