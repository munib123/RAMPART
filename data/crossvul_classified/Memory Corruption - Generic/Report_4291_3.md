# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in java
**Pair ID:** 4291_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4291_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```java
Lines 197-240 of the vulnerable file.

	private void encrypt(byte[] plaintext, int plaintextOffset,
			byte[] ciphertext, int ciphertextOffset, int length) {
		while (length > 0) {
			int tempLen = 64;
			if (tempLen > length)
				tempLen = length;
			ChaChaCore.hash(output, input);
			xorBlock(plaintext, plaintextOffset, ciphertext, ciphertextOffset, tempLen, output);
			if (++(input[12]) == 0)
				++(input[13]);
			plaintextOffset += tempLen;
			ciphertextOffset += tempLen;
			length -= tempLen;
		}
	}

	@Override
	public int encryptWithAd(byte[] ad, byte[] plaintext, int plaintextOffset,
			byte[] ciphertext, int ciphertextOffset, int length) throws ShortBufferException {
		int space;
		if (ciphertextOffset > ciphertext.length)
			space = 0;
		else
			space = ciphertext.length - ciphertextOffset;
		if (!haskey) {
			// The key is not set yet - return the plaintext as-is.
			if (length > space)
				throw new ShortBufferException();
			if (plaintext != ciphertext || plaintextOffset != ciphertextOffset)
				System.arraycopy(plaintext, plaintextOffset, ciphertext, ciphertextOffset, length);
			return length;
		}
		if (space < 16 || length > (space - 16))
			throw new ShortBufferException();
		setup(ad);
		encrypt(plaintext, plaintextOffset, ciphertext, ciphertextOffset, length);
		poly.update(ciphertext, ciphertextOffset, length);
		finish(ad, length);
		System.arraycopy(polyKey, 0, ciphertext, ciphertextOffset + length, 16);
		return length + 16;
	}

	@Override
	public int decryptWithAd(byte[] ad, byte[] ciphertext,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -214,10 +214,11 @@
 	public int encryptWithAd(byte[] ad, byte[] plaintext, int plaintextOffset,
 			byte[] ciphertext, int ciphertextOffset, int length) throws ShortBufferException {
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
 		if (!haskey) {
 			// The key is not set yet - return the plaintext as-is.
 			if (length > space)
@@ -241,16 +242,15 @@
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
 		if (!haskey) {
 			// The key is not set yet - return the ciphertext as-is.
 			if (length > space)
```
