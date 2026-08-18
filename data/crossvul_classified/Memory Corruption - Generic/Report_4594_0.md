# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 4594_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4594_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 33-73 of the vulnerable file.

    AssertMsg( crypto_aead_aes256gcm_is_available() == 1, "No hardware AES support on this CPU." );
    AssertMsg( cbKey == crypto_aead_aes256gcm_KEYBYTES, "AES key sizes other than 256 are unsupported." );
    AssertMsg( cbIV == crypto_aead_aes256gcm_NPUBBYTES, "Nonce size is unsupported" );

    if(m_ctx == nullptr)
    {
        m_ctx = sodium_malloc( sizeof(crypto_aead_aes256gcm_state) );
    }

    crypto_aead_aes256gcm_beforenm( static_cast<crypto_aead_aes256gcm_state*>( m_ctx ), static_cast<const unsigned char*>( pKey ) );

    return true;
}

bool AES_GCM_EncryptContext::Encrypt(
	const void *pPlaintextData, size_t cbPlaintextData,
	const void *pIV,
	void *pEncryptedDataAndTag, uint32 *pcbEncryptedDataAndTag,
	const void *pAdditionalAuthenticationData, size_t cbAuthenticationData
) {
    unsigned long long pcbEncryptedDataAndTag_longlong = *pcbEncryptedDataAndTag;

    crypto_aead_aes256gcm_encrypt_afternm(
		static_cast<unsigned char*>( pEncryptedDataAndTag ), &pcbEncryptedDataAndTag_longlong,
		static_cast<const unsigned char*>( pPlaintextData ), cbPlaintextData,
		static_cast<const unsigned char*>(pAdditionalAuthenticationData), cbAuthenticationData,
		nullptr,
		static_cast<const unsigned char*>( pIV ),
		static_cast<const crypto_aead_aes256gcm_state*>( m_ctx )
	);

    *pcbEncryptedDataAndTag = pcbEncryptedDataAndTag_longlong;

    return true;
}

bool AES_GCM_DecryptContext::Decrypt(
	const void *pEncryptedDataAndTag, size_t cbEncryptedDataAndTag,
	const void *pIV,
	void *pPlaintextData, uint32 *pcbPlaintextData,
	const void *pAdditionalAuthenticationData, size_t cbAuthenticationData
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,10 +50,17 @@
 	void *pEncryptedDataAndTag, uint32 *pcbEncryptedDataAndTag,
 	const void *pAdditionalAuthenticationData, size_t cbAuthenticationData
 ) {
-    unsigned long long pcbEncryptedDataAndTag_longlong = *pcbEncryptedDataAndTag;
 
+	// Make sure caller's buffer is big enough to hold the result.
+	if ( cbPlaintextData + crypto_aead_aes256gcm_ABYTES > *pcbEncryptedDataAndTag )
+	{
+		*pcbEncryptedDataAndTag = 0;
+		return false;
+	}
+
+    unsigned long long cbEncryptedDataAndTag_longlong;
     crypto_aead_aes256gcm_encrypt_afternm(
-		static_cast<unsigned char*>( pEncryptedDataAndTag ), &pcbEncryptedDataAndTag_longlong,
+		static_cast<unsigned char*>( pEncryptedDataAndTag ), &cbEncryptedDataAndTag_longlong,
 		static_cast<const unsigned char*>( pPlaintextData ), cbPlaintextData,
 		static_cast<const unsigned char*>(pAdditionalAuthenticationData), cbAuthenticationData,
 		nullptr,
@@ -61,7 +68,7 @@
 		static_cast<const crypto_aead_aes256gcm_state*>( m_ctx )
 	);
 
-    *pcbEncryptedDataAndTag = pcbEncryptedDataAndTag_longlong;
+    *pcbEncryptedDataAndTag = cbEncryptedDataAndTag_longlong;
 
     return true;
 }
@@ -72,17 +79,23 @@
 	void *pPlaintextData, uint32 *pcbPlaintextData,
 	const void *pAdditionalAuthenticationData, size_t cbAuthenticationData
 ) {
-    unsigned long long pcbPlaintextData_longlong;
+	// Make sure caller's buffer is big enough to hold the result
+	if ( cbEncryptedDataAndTag > *pcbPlaintextData + crypto_aead_aes256gcm_ABYTES )
+	{
+		*pcbPlaintextData = 0;
+		return false;
+	}
 
+    unsigned long long cbPlaintextData_longlong;
     const int nDecryptResult = crypto_aead_aes256gcm_decrypt_afternm(
-		static_cast<unsigned char*>( pPlaintextData ), &pcbPlaintextData_longlong,
+		static_cast<unsigned char*>( pPlaintextData ), &cbPlaintextData_longlong,
 		nullptr,
 		static_cast<const unsigned char*>( pEncryptedDataAndTag ), cbEncryptedDataAndTag,
 		static_cast<const unsigned char*>( pAdditionalAuthenticationData ), cbAuthenticationData,
 		static_cast<const unsigned char*>( pIV ), static_cast<const crypto_aead_aes256gcm_state*>( m_ctx )
 	);
 
-    *pcbPlaintextData = pcbPlaintextData_longlong;
+    *pcbPlaintextData = cbPlaintextData_longlong;
 
     return nDecryptResult == 0;
 }
```
