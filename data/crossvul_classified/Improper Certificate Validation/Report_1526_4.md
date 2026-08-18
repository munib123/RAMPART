# CrossVul Fix Pair: Improper Certificate Validation in csharp
**Pair ID:** 1526_4
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1526_4`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```csharp
Lines 106-146 of the vulnerable file.

				preMasterSecret, "master secret", this.Context.RandomCS, 48);

			DebugHelper.WriteLine(">>>> MasterSecret", this.Context.MasterSecret);
		}

		public override void ComputeKeys()
		{
			// Create keyblock
			TlsStream keyBlock = new TlsStream(
				this.PRF(
				this.Context.MasterSecret, 
				"key expansion",
				this.Context.RandomSC,
				this.KeyBlockSize));

			this.Context.Negotiating.ClientWriteMAC = keyBlock.ReadBytes(this.HashSize);
			this.Context.Negotiating.ServerWriteMAC = keyBlock.ReadBytes(this.HashSize);
			this.Context.ClientWriteKey = keyBlock.ReadBytes(this.KeyMaterialSize);
			this.Context.ServerWriteKey = keyBlock.ReadBytes(this.KeyMaterialSize);

			if (!this.IsExportable)
			{
				if (this.IvSize != 0)
				{
					this.Context.ClientWriteIV = keyBlock.ReadBytes(this.IvSize);
					this.Context.ServerWriteIV = keyBlock.ReadBytes(this.IvSize);
				}
				else
				{
					this.Context.ClientWriteIV = CipherSuite.EmptyArray;
					this.Context.ServerWriteIV = CipherSuite.EmptyArray;
				}
			}
			else
			{
				// Generate final write keys
				byte[] finalClientWriteKey	= PRF(this.Context.ClientWriteKey, "client write key", this.Context.RandomCS, this.ExpandedKeyMaterialSize);
				byte[] finalServerWriteKey	= PRF(this.Context.ServerWriteKey, "server write key", this.Context.RandomCS, this.ExpandedKeyMaterialSize);
				
				this.Context.ClientWriteKey	= finalClientWriteKey;
				this.Context.ServerWriteKey	= finalServerWriteKey;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -123,45 +123,15 @@
 			this.Context.ClientWriteKey = keyBlock.ReadBytes(this.KeyMaterialSize);
 			this.Context.ServerWriteKey = keyBlock.ReadBytes(this.KeyMaterialSize);
 
-			if (!this.IsExportable)
+			if (this.IvSize != 0)
 			{
-				if (this.IvSize != 0)
-				{
-					this.Context.ClientWriteIV = keyBlock.ReadBytes(this.IvSize);
-					this.Context.ServerWriteIV = keyBlock.ReadBytes(this.IvSize);
-				}
-				else
-				{
-					this.Context.ClientWriteIV = CipherSuite.EmptyArray;
-					this.Context.ServerWriteIV = CipherSuite.EmptyArray;
-				}
+				this.Context.ClientWriteIV = keyBlock.ReadBytes(this.IvSize);
+				this.Context.ServerWriteIV = keyBlock.ReadBytes(this.IvSize);
 			}
 			else
 			{
-				// Generate final write keys
-				byte[] finalClientWriteKey	= PRF(this.Context.ClientWriteKey, "client write key", this.Context.RandomCS, this.ExpandedKeyMaterialSize);
-				byte[] finalServerWriteKey	= PRF(this.Context.ServerWriteKey, "server write key", this.Context.RandomCS, this.ExpandedKeyMaterialSize);
-				
-				this.Context.ClientWriteKey	= finalClientWriteKey;
-				this.Context.ServerWriteKey	= finalServerWriteKey;
-
-				if (this.IvSize > 0) 
-				{
-					// Generate IV block
-					byte[] ivBlock = PRF(CipherSuite.EmptyArray, "IV block", this.Context.RandomCS, this.IvSize*2);
-
-					// Generate IV keys
-					this.Context.ClientWriteIV = new byte[this.IvSize];				
-					Buffer.BlockCopy(ivBlock, 0, this.Context.ClientWriteIV, 0, this.Context.ClientWriteIV.Length);
-
-					this.Context.ServerWriteIV = new byte[this.IvSize];
-					Buffer.BlockCopy(ivBlock, this.IvSize, this.Context.ServerWriteIV, 0, this.Context.ServerWriteIV.Length);
-				}
-				else 
-				{
-					this.Context.ClientWriteIV = CipherSuite.EmptyArray;
-					this.Context.ServerWriteIV = CipherSuite.EmptyArray;
-				}
+				this.Context.ClientWriteIV = CipherSuite.EmptyArray;
+				this.Context.ServerWriteIV = CipherSuite.EmptyArray;
 			}
 
 			DebugHelper.WriteLine(">>>> KeyBlock", keyBlock.ToArray());
```
