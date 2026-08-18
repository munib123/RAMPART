# CrossVul Fix Pair: Improper Certificate Validation in csharp
**Pair ID:** 1526_3
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1526_3`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```csharp
Lines 216-265 of the vulnerable file.

		}

		internal override void EndNegotiateHandshake(IAsyncResult asyncResult)
		{
			// Receive Client Hello message and ignore it
			this.protocol.EndReceiveRecord(asyncResult);

			// If received message is not an ClientHello send a
			// Fatal Alert
			if (this.context.LastHandshakeMsg != HandshakeType.ClientHello)
			{
				this.protocol.SendAlert(AlertDescription.UnexpectedMessage);
			}

			// Send ServerHello message
			this.protocol.SendRecord(HandshakeType.ServerHello);

			// Send ServerCertificate message
			this.protocol.SendRecord(HandshakeType.Certificate);

			// If the negotiated cipher is a KeyEx cipher send ServerKeyExchange
			if (this.context.Negotiating.Cipher.IsExportable)
			{
				this.protocol.SendRecord(HandshakeType.ServerKeyExchange);
			}

			// If the negotiated cipher is a KeyEx cipher or
			// the client certificate is required send the CertificateRequest message
			if (this.context.Negotiating.Cipher.IsExportable ||
				((ServerContext)this.context).ClientCertificateRequired ||
				((ServerContext)this.context).RequestClientCertificate)
			{
				this.protocol.SendRecord(HandshakeType.CertificateRequest);
			}

			// Send ServerHelloDone message
			this.protocol.SendRecord(HandshakeType.ServerHelloDone);

			// Receive client response, until the Client Finished message
			// is received. IE can be interrupted at this stage and never
			// complete the handshake
			while (this.context.LastHandshakeMsg != HandshakeType.Finished)
			{
				byte[] record = this.protocol.ReceiveRecord(this.innerStream);
				if ((record == null) || (record.Length == 0))
				{
					throw new TlsException(
						AlertDescription.HandshakeFailiure,
						"The client stopped the handshake.");
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -233,16 +233,8 @@
 			// Send ServerCertificate message
 			this.protocol.SendRecord(HandshakeType.Certificate);
 
-			// If the negotiated cipher is a KeyEx cipher send ServerKeyExchange
-			if (this.context.Negotiating.Cipher.IsExportable)
-			{
-				this.protocol.SendRecord(HandshakeType.ServerKeyExchange);
-			}
-
-			// If the negotiated cipher is a KeyEx cipher or
-			// the client certificate is required send the CertificateRequest message
-			if (this.context.Negotiating.Cipher.IsExportable ||
-				((ServerContext)this.context).ClientCertificateRequired ||
+			// If the client certificate is required send the CertificateRequest message
+			if (((ServerContext)this.context).ClientCertificateRequired ||
 				((ServerContext)this.context).RequestClientCertificate)
 			{
 				this.protocol.SendRecord(HandshakeType.CertificateRequest);
```
