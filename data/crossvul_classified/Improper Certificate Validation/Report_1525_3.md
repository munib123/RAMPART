# CrossVul Fix Pair: Improper Certificate Validation in csharp
**Pair ID:** 1525_3
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1525_3`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```csharp
Lines 16-56 of the vulnerable file.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Globalization;
using System.IO;

using Mono.Security.Protocol.Tls.Handshake;
using Mono.Security.Protocol.Tls.Handshake.Server;

namespace Mono.Security.Protocol.Tls
{
	internal class ServerRecordProtocol : RecordProtocol
	{
		#region Constructors

		public ServerRecordProtocol(
			Stream			innerStream, 
			ServerContext	context) : base(innerStream, context)
		{
		}

		#endregion

		#region Send Messages

		public override HandshakeMessage GetMessage(HandshakeType type)
		{
			// Create and process the record message
			HandshakeMessage msg = this.createServerHandshakeMessage(type);

			return msg;
		}

		#endregion
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,6 +33,8 @@
 {
 	internal class ServerRecordProtocol : RecordProtocol
 	{
+		TlsClientCertificate cert;
+		
 		#region Constructors
 
 		public ServerRecordProtocol(
@@ -93,30 +95,45 @@
 		private HandshakeMessage createClientHandshakeMessage(
 			HandshakeType type, byte[] buffer)
 		{
+			var last = context.LastHandshakeMsg;
 			switch (type)
 			{
 				case HandshakeType.ClientHello:
 					return new TlsClientHello(this.context, buffer);
 
 				case HandshakeType.Certificate:
-					return new TlsClientCertificate(this.context, buffer);
+					if (last != HandshakeType.ClientHello)
+						break;
+					cert = new TlsClientCertificate(this.context, buffer);
+					return cert;
 
 				case HandshakeType.ClientKeyExchange:
-					return new TlsClientKeyExchange(this.context, buffer);
+					if (last == HandshakeType.ClientHello || last == HandshakeType.Certificate)
+						return new TlsClientKeyExchange(this.context, buffer);
+					break;
 
 				case HandshakeType.CertificateVerify:
-					return new TlsClientCertificateVerify(this.context, buffer);
+					if (last == HandshakeType.ClientKeyExchange && cert != null)
+						return new TlsClientCertificateVerify(this.context, buffer);
+					break;
 
 				case HandshakeType.Finished:
-					return new TlsClientFinished(this.context, buffer);
-
+					// Certificates are optional, but if provided, they should send a CertificateVerify
+					bool check = (cert == null) ? (last == HandshakeType.ClientKeyExchange) : (last == HandshakeType.CertificateVerify);
+					// ChangeCipherSpecDone is not an handshake message (it's a content type) but still needs to be happens before finished
+					if (check && context.ChangeCipherSpecDone) {
+						context.ChangeCipherSpecDone = false;
+						return new TlsClientFinished(this.context, buffer);
+					}
+					break;
+					
 				default:
-					throw new TlsException(
-						AlertDescription.UnexpectedMessage,
-						String.Format(CultureInfo.CurrentUICulture,
-							"Unknown server handshake message received ({0})", 
-							type.ToString()));
+					throw new TlsException(AlertDescription.UnexpectedMessage, String.Format(CultureInfo.CurrentUICulture,
+														 "Unknown server handshake message received ({0})", 
+														 type.ToString()));
+					break;
 			}
+			throw new TlsException (AlertDescription.HandshakeFailiure, String.Format ("Protocol error, unexpected protocol transition from {0} to {1}", last, type));
 		}
 
 		private HandshakeMessage createServerHandshakeMessage(
```
