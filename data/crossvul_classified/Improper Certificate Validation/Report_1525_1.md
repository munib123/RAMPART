# CrossVul Fix Pair: Improper Certificate Validation in csharp
**Pair ID:** 1525_1
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1525_1`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```csharp
Lines 104-144 of the vulnerable file.

		private RandomNumberGenerator random;

		// Record protocol
		private RecordProtocol recordProtocol;

		#endregion

		#region Properties

		public bool AbbreviatedHandshake
		{
			get { return abbreviatedHandshake; }
			set { abbreviatedHandshake = value; }
		}

		public bool	ProtocolNegotiated
		{
			get { return this.protocolNegotiated; }
			set { this.protocolNegotiated = value; }
		}

		public SecurityProtocolType SecurityProtocol
		{
			get 
			{
				if ((this.securityProtocol & SecurityProtocolType.Tls) == SecurityProtocolType.Tls ||	
					(this.securityProtocol & SecurityProtocolType.Default) == SecurityProtocolType.Default)
				{
					return SecurityProtocolType.Tls;
				}
				else
				{
					if ((this.securityProtocol & SecurityProtocolType.Ssl3) == SecurityProtocolType.Ssl3)
					{
						return SecurityProtocolType.Ssl3;
					}
				}

				throw new NotSupportedException("Unsupported security protocol type");
			}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,6 +122,8 @@
 			set { this.protocolNegotiated = value; }
 		}
 
+		public bool ChangeCipherSpecDone { get; set; }
+
 		public SecurityProtocolType SecurityProtocol
 		{
 			get 
```
