# CrossVul Fix Pair: Improper Certificate Validation in csharp
**Pair ID:** 1526_1
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1526_1`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```csharp
Lines 143-189 of the vulnerable file.

					else
					{
						this.SendAlert(
							AlertLevel.Warning,
							AlertDescription.NoRenegotiation);
					}
					return null;

				case HandshakeType.ServerHello:
					if (last != HandshakeType.HelloRequest)
						break;
					return new TlsServerHello(this.context, buffer);

					// Optional
				case HandshakeType.Certificate:
					if (last != HandshakeType.ServerHello)
						break;
					return new TlsServerCertificate(this.context, buffer);

					// Optional
				case HandshakeType.ServerKeyExchange:
					// only for RSA_EXPORT
					if (last == HandshakeType.Certificate && context.Current.Cipher.IsExportable)
						return new TlsServerKeyExchange(this.context, buffer);
					break;

					// Optional
				case HandshakeType.CertificateRequest:
					if (last == HandshakeType.ServerKeyExchange || last == HandshakeType.Certificate)
						return new TlsServerCertificateRequest(this.context, buffer);
					break;

				case HandshakeType.ServerHelloDone:
					if (last == HandshakeType.CertificateRequest || last == HandshakeType.Certificate || last == HandshakeType.ServerHello)
						return new TlsServerHelloDone(this.context, buffer);
					break;

				case HandshakeType.Finished:
					// depends if a full (ServerHelloDone) or an abbreviated handshake (ServerHello) is being done
					bool check = context.AbbreviatedHandshake ? (last == HandshakeType.ServerHello) : (last == HandshakeType.ServerHelloDone);
					// ChangeCipherSpecDone is not an handshake message (it's a content type) but still needs to be happens before finished
					if (check && context.ChangeCipherSpecDone) {
						context.ChangeCipherSpecDone = false;
						return new TlsServerFinished (this.context, buffer);
					}
					break;
					
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -160,13 +160,6 @@
 					return new TlsServerCertificate(this.context, buffer);
 
 					// Optional
-				case HandshakeType.ServerKeyExchange:
-					// only for RSA_EXPORT
-					if (last == HandshakeType.Certificate && context.Current.Cipher.IsExportable)
-						return new TlsServerKeyExchange(this.context, buffer);
-					break;
-
-					// Optional
 				case HandshakeType.CertificateRequest:
 					if (last == HandshakeType.ServerKeyExchange || last == HandshakeType.Certificate)
 						return new TlsServerCertificateRequest(this.context, buffer);
```
