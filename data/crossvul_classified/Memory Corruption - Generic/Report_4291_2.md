# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in java
**Pair ID:** 4291_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4291_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```java
Lines 201-244 of the vulnerable file.

		try {
			cipher.update(hashKey, 0, 16, hashKey, 0);
		} catch (ShortBufferException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		}
		
		// Initialize the GHASH with the associated data value.
		ghash.reset();
		if (ad != null) {
			ghash.update(ad, 0, ad.length);
			ghash.pad();
		}
	}

	@Override
	public int encryptWithAd(byte[] ad, byte[] plaintext, int plaintextOffset,
			byte[] ciphertext, int ciphertextOffset, int length)
			throws ShortBufferException {
		int space;
		if (ciphertextOffset > ciphertext.length)
			space = 0;
		else
			space = ciphertext.length - ciphertextOffset;
		if (keySpec == null) {
			// The key is not set yet - return the plaintext as-is.
			if (length > space)
				throw new ShortBufferException();
			if (plaintext != ciphertext || plaintextOffset != ciphertextOffset)
				System.arraycopy(plaintext, plaintextOffset, ciphertext, ciphertextOffset, length);
			return length;
		}
		if (space < 16 || length > (space - 16))
			throw new ShortBufferException();
		try {
			setup(ad);
			int result = cipher.update(plaintext, plaintextOffset, length, ciphertext, ciphertextOffset);
			cipher.doFinal(ciphertext, ciphertextOffset + result);
		} catch (InvalidKeyException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
		} catch (InvalidAlgorithmParameterException e) {
			// Shouldn't happen.
			throw new IllegalStateException(e);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -218,10 +218,11 @@
 			byte[] ciphertext, int ciphertextOffset, int length)
 			throws ShortBufferException {
 		int space;
-		if (ciphertextOffset > ciphertext.length)
-			space = 0;
-		else
-			space = ciphertext.length - ciphertextOffset;
+		if (ciphertextOffset < 0 || ciphertextOffset > ciphertext.length)
+			throw new IllegalArgumentException();
+		if (length < 0 || plaintextOffset < 0 || plaintextOffset > plaintext.length)
+			throw new IllegalArgumentException();
+		space = ciphertext.length - ciphertextOffset;
 		if (keySpec == null) {
 			// The key is not set yet - return the plaintext as-is.
 			if (length > space)
@@ -262,16 +263,15 @@
 			int ciphertextOffset, byte[] plaintext, int plaintextOffset,
 			int length) throws ShortBufferException, BadPaddingException {
 		int space;
-		if (ciphertextOffset > ciphertext.length)
-			space = 0;
+		if (ciphertextOffset < 0 || ciphertextOffset > ciphertext.length)
+			throw new IllegalArgumentException();
 		else
 			space = ciphertext.length - ciphertextOffset;
 		if (length > space)
 			throw new ShortBufferException();
-		if (plaintextOffset > plaintext.length)
-			space = 0;
-		else
-			space = plaintext.length - plaintextOffset;
+		if (length < 0 || plaintextOffset < 0 || plaintextOffset > plaintext.length)
+			throw new IllegalArgumentException();
+		space = plaintext.length - plaintextOffset;
 		if (keySpec == null) {
 			// The key is not set yet - return the ciphertext as-is.
 			if (length > space)
```
