# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4593_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4593_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 73-113 of the vulnerable file.

constexpr int k_cbMaxBufferedReceiveReliableData = k_cbMaxMessageSizeRecv + 64*1024;
constexpr int k_nMaxReliableStreamGaps_Extend = 30; // Discard reliable data past the end of the stream, if it would cause us to get too many gaps
constexpr int k_nMaxReliableStreamGaps_Fragment = 20; // Discard reliable data that is filling in the middle of a hole, if it would cause the number of gaps to exceed this number
constexpr int k_nMaxPacketGaps = 62; // Don't bother tracking more than N gaps.  Instead, we will end up NACKing some packets that we actually did receive.  This should not break the protocol, but it protects us from malicious sender

// Hang on to at most N unreliable segments.  When packets are dropping
// and unreliable messages being fragmented, we will accumulate old pieces
// of unreliable messages that we retain in hopes that we will get the
// missing piece and reassemble the whole message.  At a certain point we
// must give up and discard them.  We use a simple strategy of just limiting
// the max total number.  In reality large unreliable messages are just a very bad
// idea, since the odds of the message dropping increase exponentially with the
// number of packets.  With 20 packets, even 1% packet loss becomes ~80% message
// loss.  (Assuming naive fragmentation and reassembly and no forward
// error correction.)
constexpr int k_nMaxBufferedUnreliableSegments = 20;

// If app tries to send a message larger than N bytes unreliably,
// complain about it, and automatically convert to reliable.
// About 15 segments.
constexpr int k_cbMaxUnreliableMsgSize = 15*1100;

class CSteamNetworkConnectionBase;
class CConnectionTransport;
struct SteamNetworkingMessageQueue;

/// Actual implementation of SteamNetworkingMessage_t, which is the API
/// visible type.  Has extra fields needed to put the message into intrusive
/// linked lists.
class CSteamNetworkingMessage : public SteamNetworkingMessage_t
{
public:
	static CSteamNetworkingMessage *New( CSteamNetworkConnectionBase *pParent, uint32 cbSize, int64 nMsgNum, int nFlags, SteamNetworkingMicroseconds usecNow );
	static CSteamNetworkingMessage *New( uint32 cbSize );
	static void DefaultFreeData( SteamNetworkingMessage_t *pMsg );

	/// OK to delay sending this message until this time.  Set to zero to explicitly force
	/// Nagle timer to expire and send now (but this should behave the same as if the
	/// timer < usecNow).  If the timer is cleared, then all messages with lower message numbers
	/// are also cleared.
	inline SteamNetworkingMicroseconds SNPSend_UsecNagle() const { return m_usecTimeReceived; }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,7 +90,14 @@
 // If app tries to send a message larger than N bytes unreliably,
 // complain about it, and automatically convert to reliable.
 // About 15 segments.
-constexpr int k_cbMaxUnreliableMsgSize = 15*1100;
+constexpr int k_cbMaxUnreliableMsgSizeSend = 15*1100;
+
+// Max possible size of an unreliable segment we could receive.
+constexpr int k_cbMaxUnreliableSegmentSizeRecv = k_cbSteamNetworkingSocketsMaxPlaintextPayloadRecv;
+
+// Largest possible total unreliable message we can receive, based on the constraints above
+constexpr int k_cbMaxUnreliableMsgSizeRecv = k_nMaxBufferedUnreliableSegments*k_cbMaxUnreliableSegmentSizeRecv;
+COMPILE_TIME_ASSERT( k_cbMaxUnreliableMsgSizeRecv > k_cbMaxUnreliableMsgSizeSend + 4096 ); // Postel's law; confirm how much slack we have here
 
 class CSteamNetworkConnectionBase;
 class CConnectionTransport;
@@ -468,7 +475,7 @@
 {
 	int m_cbSegSize = -1;
 	bool m_bLast = false;
-	char m_buf[ k_cbSteamNetworkingSocketsMaxPlaintextPayloadRecv ];
+	char m_buf[ k_cbMaxUnreliableSegmentSizeRecv ];
 };
 
 struct SSNPPacketGap
```
