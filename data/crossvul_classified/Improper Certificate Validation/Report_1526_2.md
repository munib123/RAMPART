# CrossVul Fix Pair: Improper Certificate Validation in csharp
**Pair ID:** 1526_2
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1526_2`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```csharp
Lines 173-213 of the vulnerable file.

				}
						
				byte[] block = this.prf(this.Context.MasterSecret, label.ToString(), this.Context.RandomSC);

				int size = (tmp.Length + block.Length) > this.KeyBlockSize ? (this.KeyBlockSize - (int)tmp.Length) : block.Length;
				
				tmp.Write(block, 0, size);

				labelChar++;
				count++;
			}
			
			// Create keyblock
			TlsStream keyBlock = new TlsStream(tmp.ToArray());			
			
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
				HashAlgorithm md5 = MD5.Create();

				int keySize = (md5.HashSize >> 3); //in bytes not bits
				byte[] temp = new byte [keySize];

				// Generate final write keys
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -190,59 +190,15 @@
 			this.Context.ClientWriteKey = keyBlock.ReadBytes(this.KeyMaterialSize);
 			this.Context.ServerWriteKey = keyBlock.ReadBytes(this.KeyMaterialSize);
 
-			if (!this.IsExportable)
-			{
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
+			if (this.IvSize != 0)
+			{
+				this.Context.ClientWriteIV = keyBlock.ReadBytes(this.IvSize);
+				this.Context.ServerWriteIV = keyBlock.ReadBytes(this.IvSize);
 			}
 			else
 			{
-				HashAlgorithm md5 = MD5.Create();
-
-				int keySize = (md5.HashSize >> 3); //in bytes not bits
-				byte[] temp = new byte [keySize];
-
-				// Generate final write keys
-				md5.TransformBlock(this.Context.ClientWriteKey, 0, this.Context.ClientWriteKey.Length, temp, 0);
-				md5.TransformFinalBlock(this.Context.RandomCS, 0, this.Context.RandomCS.Length);
-				byte[] finalClientWriteKey = new byte[this.ExpandedKeyMaterialSize];
-				Buffer.BlockCopy(md5.Hash, 0, finalClientWriteKey, 0, this.ExpandedKeyMaterialSize);
-
-				md5.Initialize();
-				md5.TransformBlock(this.Context.ServerWriteKey, 0, this.Context.ServerWriteKey.Length, temp, 0);
-				md5.TransformFinalBlock(this.Context.RandomSC, 0, this.Context.RandomSC.Length);
-				byte[] finalServerWriteKey = new byte[this.ExpandedKeyMaterialSize];
-				Buffer.BlockCopy(md5.Hash, 0, finalServerWriteKey, 0, this.ExpandedKeyMaterialSize);
-				
-				this.Context.ClientWriteKey = finalClientWriteKey;
-				this.Context.ServerWriteKey = finalServerWriteKey;
-
-				// Generate IV keys
-				if (this.IvSize > 0) 
-				{
-					md5.Initialize();
-					temp = md5.ComputeHash(this.Context.RandomCS, 0, this.Context.RandomCS.Length);
-					this.Context.ClientWriteIV = new byte[this.IvSize];
-					Buffer.BlockCopy(temp, 0, this.Context.ClientWriteIV, 0, this.IvSize);
-
-					md5.Initialize();
-					temp = md5.ComputeHash(this.Context.RandomSC, 0, this.Context.RandomSC.Length);
-					this.Context.ServerWriteIV = new byte[this.IvSize];
-					Buffer.BlockCopy(temp, 0, this.Context.ServerWriteIV, 0, this.IvSize);
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
