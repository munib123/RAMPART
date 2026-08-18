# CrossVul Fix Pair: Improper Certificate Validation in csharp
**Pair ID:** 1525_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1525_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```csharp
Lines 112-152 of the vulnerable file.

					return new TlsClientCertificate(this.context);

				case HandshakeType.ClientKeyExchange:
					return new TlsClientKeyExchange(this.context);

				case HandshakeType.CertificateVerify:
					return new TlsClientCertificateVerify(this.context);

				case HandshakeType.Finished:
					return new TlsClientFinished(this.context);

				default:
					throw new InvalidOperationException("Unknown client handshake message type: " + type.ToString() );
			}
		}

		private HandshakeMessage createServerHandshakeMessage(
			HandshakeType type, byte[] buffer)
		{
			ClientContext context = (ClientContext)this.context;

			switch (type)
			{
				case HandshakeType.HelloRequest:
					if (context.HandshakeState != HandshakeState.Started)
					{
						context.HandshakeState = HandshakeState.None;
						// re-negotiation will occur at next read/write
						// (i.e. not during an existing encode/decode op)
					}
					else
					{
						this.SendAlert(
							AlertLevel.Warning,
							AlertDescription.NoRenegotiation);
					}
					return null;

				case HandshakeType.ServerHello:
					return new TlsServerHello(this.context, buffer);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,6 +129,7 @@
 			HandshakeType type, byte[] buffer)
 		{
 			ClientContext context = (ClientContext)this.context;
+			var last = context.LastHandshakeMsg;
 
 			switch (type)
 			{
@@ -148,23 +149,44 @@
 					return null;
 
 				case HandshakeType.ServerHello:
+					if (last != HandshakeType.HelloRequest)
+						break;
 					return new TlsServerHello(this.context, buffer);
 
+					// Optional
 				case HandshakeType.Certificate:
+					if (last != HandshakeType.ServerHello)
+						break;
 					return new TlsServerCertificate(this.context, buffer);
 
+					// Optional
 				case HandshakeType.ServerKeyExchange:
-					return new TlsServerKeyExchange(this.context, buffer);
-
+					// only for RSA_EXPORT
+					if (last == HandshakeType.Certificate && context.Current.Cipher.IsExportable)
+						return new TlsServerKeyExchange(this.context, buffer);
+					break;
+
+					// Optional
 				case HandshakeType.CertificateRequest:
-					return new TlsServerCertificateRequest(this.context, buffer);
+					if (last == HandshakeType.ServerKeyExchange || last == HandshakeType.Certificate)
+						return new TlsServerCertificateRequest(this.context, buffer);
+					break;
 
 				case HandshakeType.ServerHelloDone:
-					return new TlsServerHelloDone(this.context, buffer);
+					if (last == HandshakeType.CertificateRequest || last == HandshakeType.Certificate || last == HandshakeType.ServerHello)
+						return new TlsServerHelloDone(this.context, buffer);
+					break;
 
 				case HandshakeType.Finished:
-					return new TlsServerFinished(this.context, buffer);
-
+					// depends if a full (ServerHelloDone) or an abbreviated handshake (ServerHello) is being done
+					bool check = context.AbbreviatedHandshake ? (last == HandshakeType.ServerHello) : (last == HandshakeType.ServerHelloDone);
+					// ChangeCipherSpecDone is not an handshake message (it's a content type) but still needs to be happens before finished
+					if (check && context.ChangeCipherSpecDone) {
+						context.ChangeCipherSpecDone = false;
+						return new TlsServerFinished (this.context, buffer);
+					}
+					break;
+					
 				default:
 					throw new TlsException(
 						AlertDescription.UnexpectedMessage,
@@ -172,6 +194,7 @@
 							"Unknown server handshake message received ({0})", 
 							type.ToString()));
 			}
+			throw new TlsException (AlertDescription.HandshakeFailiure, String.Format ("Protocol error, unexpected protocol transition from {0} to {1}", last, type));
 		}
 
 		#endregion
```
