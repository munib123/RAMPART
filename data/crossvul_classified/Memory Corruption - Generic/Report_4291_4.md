# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in java
**Pair ID:** 4291_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4291_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```java
Lines 83-123 of the vulnerable file.

	/**
	 * Encrypts a plaintext buffer using the cipher and a block of associated data.
	 * 
	 * @param ad The associated data, or null if there is none.
	 * @param plaintext The buffer containing the plaintext to encrypt.
	 * @param plaintextOffset The offset within the plaintext buffer of the
	 * first byte or plaintext data.
	 * @param ciphertext The buffer to place the ciphertext in.  This can
	 * be the same as the plaintext buffer.
	 * @param ciphertextOffset The first offset within the ciphertext buffer
	 * to place the ciphertext and the MAC tag.
	 * @param length The length of the plaintext.
	 * @return The length of the ciphertext plus the MAC tag, or -1 if the
	 * ciphertext buffer is not large enough to hold the result.
	 * 
	 * @throws ShortBufferException The ciphertext buffer does not have
	 * enough space to hold the ciphertext plus MAC.
	 * 
	 * @throws IllegalStateException The nonce has wrapped around.
	 * 
	 * The plaintext and ciphertext buffers can be the same for in-place
	 * encryption.  In that case, plaintextOffset must be identical to
	 * ciphertextOffset.
	 * 
	 * There must be enough space in the ciphertext buffer to accomodate
	 * length + getMACLength() bytes of data starting at ciphertextOffset.
	 */
	int encryptWithAd(byte[] ad, byte[] plaintext, int plaintextOffset, byte[] ciphertext, int ciphertextOffset, int length) throws ShortBufferException;

	/**
	 * Decrypts a ciphertext buffer using the cipher and a block of associated data.
	 * 
	 * @param ad The associated data, or null if there is none.
	 * @param ciphertext The buffer containing the ciphertext to decrypt.
	 * @param ciphertextOffset The offset within the ciphertext buffer of
	 * the first byte of ciphertext data.
	 * @param plaintext The buffer to place the plaintext in.  This can be
	 * the same as the ciphertext buffer.
	 * @param plaintextOffset The first offset within the plaintext buffer
	 * to place the plaintext.
	 * @param length The length of the incoming ciphertext plus the MAC tag.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,6 +100,8 @@
 	 * 
 	 * @throws IllegalStateException The nonce has wrapped around.
 	 * 
+	 * @throws IllegalArgumentException One of the parameters is out of range.
+	 *
 	 * The plaintext and ciphertext buffers can be the same for in-place
 	 * encryption.  In that case, plaintextOffset must be identical to
 	 * ciphertextOffset.
@@ -130,6 +132,8 @@
 	 * 
 	 * @throws IllegalStateException The nonce has wrapped around.
 	 * 
+	 * @throws IllegalArgumentException One of the parameters is out of range.
+	 *
 	 * The plaintext and ciphertext buffers can be the same for in-place
 	 * decryption.  In that case, ciphertextOffset must be identical to
 	 * plaintextOffset.
```
