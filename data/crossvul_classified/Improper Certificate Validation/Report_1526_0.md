# CrossVul Fix Pair: Improper Certificate Validation in csharp
**Pair ID:** 1526_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1526_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```csharp
Lines 99-143 of the vulnerable file.

				}
			}
			return allowed;
		}

		#region Private Static Methods

		private static CipherSuiteCollection GetTls1SupportedCiphers()
		{
			CipherSuiteCollection scs = new CipherSuiteCollection(SecurityProtocolType.Tls);

			// Supported ciphers
			scs.Add((0x00 << 0x08) | 0x35, "TLS_RSA_WITH_AES_256_CBC_SHA", CipherAlgorithmType.Rijndael, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, false, true, 32, 32, 256, 16, 16);
			scs.Add((0x00 << 0x08) | 0x2F, "TLS_RSA_WITH_AES_128_CBC_SHA", CipherAlgorithmType.Rijndael, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, false, true, 16, 16, 128, 16, 16);
			scs.Add((0x00 << 0x08) | 0x0A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", CipherAlgorithmType.TripleDes, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, false, true, 24, 24, 168, 8, 8);
			scs.Add((0x00 << 0x08) | 0x05, "TLS_RSA_WITH_RC4_128_SHA", CipherAlgorithmType.Rc4, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, false, false, 16, 16, 128, 0, 0);
			scs.Add((0x00 << 0x08) | 0x04, "TLS_RSA_WITH_RC4_128_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, false, false, 16, 16, 128, 0, 0);
			scs.Add((0x00 << 0x08) | 0x09, "TLS_RSA_WITH_DES_CBC_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, false, true, 8, 8, 56, 8, 8);
			
			// Supported exportable ciphers
			scs.Add((0x00 << 0x08) | 0x03, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 5, 16, 40, 0, 0);
			scs.Add((0x00 << 0x08) | 0x06, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 16, 40, 8, 8);
			scs.Add((0x00 << 0x08) | 0x08, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 8, 40, 8, 8);
			scs.Add((0x00 << 0x08) | 0x60, "TLS_RSA_EXPORT_WITH_RC4_56_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
			scs.Add((0x00 << 0x08) | 0x61, "TLS_RSA_EXPORT_WITH_RC2_CBC_56_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 7, 16, 56, 8, 8);
			// 56 bits but we use 64 bits because of parity (DES is really 56 bits)
			scs.Add((0x00 << 0x08) | 0x62, "TLS_RSA_EXPORT_WITH_DES_CBC_56_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 8, 8, 64, 8, 8); 
			scs.Add((0x00 << 0x08) | 0x64, "TLS_RSA_EXPORT_WITH_RC4_56_SHA", CipherAlgorithmType.Rc4, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
			
			// Default CipherSuite
			// scs.Add(0, "TLS_NULL_WITH_NULL_NULL", CipherAlgorithmType.None, HashAlgorithmType.None, ExchangeAlgorithmType.None, true, false, 0, 0, 0, 0, 0);
			
			// RSA Cipher Suites
			// scs.Add((0x00 << 0x08) | 0x01, "TLS_RSA_WITH_NULL_MD5", CipherAlgorithmType.None, HashAlgorithmType.Md5, ExchangeAlgorithmType.None, true, false, 0, 0, 0, 0, 0);
			// scs.Add((0x00 << 0x08) | 0x02, "TLS_RSA_WITH_NULL_SHA", CipherAlgorithmType.None, HashAlgorithmType.Sha1, ExchangeAlgorithmType.None, true, false, 0, 0, 0, 0, 0);
			// scs.Add((0x00 << 0x08) | 0x03, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 5, 16, 40, 0, 0);
			// scs.Add((0x00 << 0x08) | 0x05, "TLS_RSA_WITH_RC4_128_SHA", CipherAlgorithmType.Rc4, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaSign, false, false, 16, 16, 128, 0, 0);
			// scs.Add((0x00 << 0x08) | 0x04, "TLS_RSA_WITH_RC4_128_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaSign, false, false, 16, 16, 128, 0, 0);			
			// scs.Add((0x00 << 0x08) | 0x06, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 16, 40, 8, 8);
... (excerpt truncated)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,14 +116,14 @@
 			scs.Add((0x00 << 0x08) | 0x09, "TLS_RSA_WITH_DES_CBC_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, false, true, 8, 8, 56, 8, 8);
 			
 			// Supported exportable ciphers
-			scs.Add((0x00 << 0x08) | 0x03, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 5, 16, 40, 0, 0);
-			scs.Add((0x00 << 0x08) | 0x06, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 16, 40, 8, 8);
-			scs.Add((0x00 << 0x08) | 0x08, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 8, 40, 8, 8);
-			scs.Add((0x00 << 0x08) | 0x60, "TLS_RSA_EXPORT_WITH_RC4_56_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
-			scs.Add((0x00 << 0x08) | 0x61, "TLS_RSA_EXPORT_WITH_RC2_CBC_56_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 7, 16, 56, 8, 8);
+			// scs.Add((0x00 << 0x08) | 0x03, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 5, 16, 40, 0, 0);
+			// scs.Add((0x00 << 0x08) | 0x06, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 16, 40, 8, 8);
+			// scs.Add((0x00 << 0x08) | 0x08, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 8, 40, 8, 8);
+			// scs.Add((0x00 << 0x08) | 0x60, "TLS_RSA_EXPORT_WITH_RC4_56_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
+			// scs.Add((0x00 << 0x08) | 0x61, "TLS_RSA_EXPORT_WITH_RC2_CBC_56_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 7, 16, 56, 8, 8);
 			// 56 bits but we use 64 bits because of parity (DES is really 56 bits)
-			scs.Add((0x00 << 0x08) | 0x62, "TLS_RSA_EXPORT_WITH_DES_CBC_56_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 8, 8, 64, 8, 8); 
-			scs.Add((0x00 << 0x08) | 0x64, "TLS_RSA_EXPORT_WITH_RC4_56_SHA", CipherAlgorithmType.Rc4, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
+			// scs.Add((0x00 << 0x08) | 0x62, "TLS_RSA_EXPORT_WITH_DES_CBC_56_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 8, 8, 64, 8, 8);
+			// scs.Add((0x00 << 0x08) | 0x64, "TLS_RSA_EXPORT_WITH_RC4_56_SHA", CipherAlgorithmType.Rc4, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
 			
 			// Default CipherSuite
 			// scs.Add(0, "TLS_NULL_WITH_NULL_NULL", CipherAlgorithmType.None, HashAlgorithmType.None, ExchangeAlgorithmType.None, true, false, 0, 0, 0, 0, 0);
@@ -195,14 +195,14 @@
 			scs.Add((0x00 << 0x08) | 0x09, "SSL_RSA_WITH_DES_CBC_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, false, true, 8, 8, 56, 8, 8);
 
 			// Supported exportable ciphers
-			scs.Add((0x00 << 0x08) | 0x03, "SSL_RSA_EXPORT_WITH_RC4_40_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 5, 16, 40, 0, 0);
-			scs.Add((0x00 << 0x08) | 0x06, "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 16, 40, 8, 8);
-			scs.Add((0x00 << 0x08) | 0x08, "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 8, 40, 8, 8);
-			scs.Add((0x00 << 0x08) | 0x60, "SSL_RSA_EXPORT_WITH_RC4_56_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
-			scs.Add((0x00 << 0x08) | 0x61, "SSL_RSA_EXPORT_WITH_RC2_CBC_56_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 7, 16, 56, 8, 8);
+			// scs.Add((0x00 << 0x08) | 0x03, "SSL_RSA_EXPORT_WITH_RC4_40_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 5, 16, 40, 0, 0);
+			// scs.Add((0x00 << 0x08) | 0x06, "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 16, 40, 8, 8);
+			// scs.Add((0x00 << 0x08) | 0x08, "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 5, 8, 40, 8, 8);
+			// scs.Add((0x00 << 0x08) | 0x60, "SSL_RSA_EXPORT_WITH_RC4_56_MD5", CipherAlgorithmType.Rc4, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
+			// scs.Add((0x00 << 0x08) | 0x61, "SSL_RSA_EXPORT_WITH_RC2_CBC_56_MD5", CipherAlgorithmType.Rc2, HashAlgorithmType.Md5, ExchangeAlgorithmType.RsaKeyX, true, true, 7, 16, 56, 8, 8);
 			// 56 bits but we use 64 bits because of parity (DES is really 56 bits)
-			scs.Add((0x00 << 0x08) | 0x62, "SSL_RSA_EXPORT_WITH_DES_CBC_56_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 8, 8, 64, 8, 8); 
-			scs.Add((0x00 << 0x08) | 0x64, "SSL_RSA_EXPORT_WITH_RC4_56_SHA", CipherAlgorithmType.Rc4, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
+			// scs.Add((0x00 << 0x08) | 0x62, "SSL_RSA_EXPORT_WITH_DES_CBC_56_SHA", CipherAlgorithmType.Des, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, true, 8, 8, 64, 8, 8);
+			// scs.Add((0x00 << 0x08) | 0x64, "SSL_RSA_EXPORT_WITH_RC4_56_SHA", CipherAlgorithmType.Rc4, HashAlgorithmType.Sha1, ExchangeAlgorithmType.RsaKeyX, true, false, 7, 16, 56, 0, 0);
 
 			// Default CipherSuite
 			// scs.Add(0, "SSL_NULL_WITH_NULL_NULL", CipherAlgorithmType.None, HashAlgorithmType.None, true, false, 0, 0, 0, 0, 0);
```
