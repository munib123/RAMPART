# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in java
**Pair ID:** 4291_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4291_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```java
Lines 168-211 of the vulnerable file.

			
			// XOR the keystream block with the plaintext to create the ciphertext.
			int temp = length;
			if (temp > 16)
				temp = 16;
			for (int index = 0; index < temp; ++index)
				ciphertext[ciphertextOffset + index] = (byte)(plaintext[plaintextOffset + index] ^ enciv[index]);
			
			// Advance to the next block.
			plaintextOffset += temp;
			ciphertextOffset += temp;
			length -= temp;
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
		encryptCTR(plaintext, plaintextOffset, ciphertext, ciphertextOffset, length);
		ghash.update(ciphertext, ciphertextOffset, length);
		ghash.pad(ad != null ? ad.length : 0, length);
		ghash.finish(ciphertext, ciphertextOffset + length, 16);
		for (int index = 0; index < 16; ++index)
			ciphertext[ciphertextOffset + length + index] ^= hashKey[index];
		return length + 16;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -185,10 +185,11 @@
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
 		if (!haskey) {
 			// The key is not set yet - return the plaintext as-is.
 			if (length > space)
@@ -214,16 +215,15 @@
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
