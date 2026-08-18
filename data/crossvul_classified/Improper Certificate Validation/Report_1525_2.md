# CrossVul Fix Pair: Improper Certificate Validation in csharp
**Pair ID:** 1525_2
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1525_2`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```csharp
Lines 71-111 of the vulnerable file.

			IAsyncResult ar = this.BeginSendRecord(type, null, null);

			this.EndSendRecord(ar);

		}

		protected abstract void ProcessHandshakeMessage(TlsStream handMsg);

		protected virtual void ProcessChangeCipherSpec ()
		{
			Context ctx = this.Context;

			// Reset sequence numbers
			ctx.ReadSequenceNumber = 0;

			if (ctx is ClientContext) {
				ctx.EndSwitchingSecurityParameters (true);
			} else {
				ctx.StartSwitchingSecurityParameters (false);
			}
		}

		public virtual HandshakeMessage GetMessage(HandshakeType type)
		{
			throw new NotSupportedException();
		}

		#endregion

		#region Receive Record Async Result
		private class ReceiveRecordAsyncResult : IAsyncResult
		{
			private object locker = new object ();
			private AsyncCallback _userCallback;
			private object _userState;
			private Exception _asyncException;
			private ManualResetEvent handle;
			private byte[] _resultingBuffer;
			private Stream _record;
			private bool completed;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,6 +88,8 @@
 			} else {
 				ctx.StartSwitchingSecurityParameters (false);
 			}
+
+			ctx.ChangeCipherSpecDone = true;
 		}
 
 		public virtual HandshakeMessage GetMessage(HandshakeType type)
@@ -347,9 +349,6 @@
 
 				// Try to read the Record Content Type
 				int type = internalResult.InitialBuffer[0];
-
-				// Set last handshake message received to None
-				this.context.LastHandshakeMsg = HandshakeType.ClientHello;
 
 				ContentType	contentType	= (ContentType)type;
 				byte[] buffer = this.ReadRecordBuffer(type, record);
@@ -457,9 +456,6 @@
 
 			// Try to read the Record Content Type
 			int type = recordTypeBuffer[0];
-
-			// Set last handshake message received to None
-			this.context.LastHandshakeMsg = HandshakeType.ClientHello;
 
 			ContentType	contentType	= (ContentType)type;
 			byte[] buffer = this.ReadRecordBuffer(type, record);
```
