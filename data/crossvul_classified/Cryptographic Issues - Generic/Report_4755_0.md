# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4755_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4755_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 1-28 of the vulnerable file.

package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

/**
 * an implementation of the AES (Rijndael), from FIPS-197.
 * <p>
 * For further details see: <a href="http://csrc.nist.gov/encryption/aes/">http://csrc.nist.gov/encryption/aes/</a>.
 *
 * This implementation is based on optimizations from Dr. Brian Gladman's paper and C code at
 * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
 *
 * There are three levels of tradeoff of speed vs memory
 * Because java has no preprocessor, they are written as three separate classes from which to choose
 *
 * The fastest uses 8Kbytes of static tables to precompute round calculations, 4 256 word tables for encryption
 * and 4 for decryption.
 *
 * The middle performance version uses only one 256 word table for each, for a total of 2Kbytes,
 * adding 12 rotate operations per round to compute the values contained in the other tables from
 * the contents of the first.
 *
 * The slowest version uses no static tables at all and computes the values in each round.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 import org.bouncycastle.crypto.DataLengthException;
 import org.bouncycastle.crypto.OutputLengthException;
 import org.bouncycastle.crypto.params.KeyParameter;
+import org.bouncycastle.util.Arrays;
 import org.bouncycastle.util.Pack;
 
 /**
@@ -415,6 +416,8 @@
     private int         C0, C1, C2, C3;
     private boolean     forEncryption;
 
+    private byte[]      s;
+
     private static final int BLOCK_SIZE = 16;
 
     /**
@@ -440,6 +443,14 @@
         {
             WorkingKey = generateWorkingKey(((KeyParameter)params).getKey(), forEncryption);
             this.forEncryption = forEncryption;
+            if (forEncryption)
+            {
+                s = Arrays.clone(S);
+            }
+            else
+            {
+                s = Arrays.clone(Si);
+            }
             return;
         }
 
@@ -578,10 +589,10 @@
 
         // the final round's table is a simple function of S so we don't use a whole other four tables for it
 
-        this.C0 = (S[r0&255]&255) ^ ((S[(r1>>8)&255]&255)<<8) ^ ((S[(r2>>16)&255]&255)<<16) ^ (S[(r3>>24)&255]<<24) ^ KW[r][0];
-        this.C1 = (S[r1&255]&255) ^ ((S[(r2>>8)&255]&255)<<8) ^ ((S[(r3>>16)&255]&255)<<16) ^ (S[(r0>>24)&255]<<24) ^ KW[r][1];
-        this.C2 = (S[r2&255]&255) ^ ((S[(r3>>8)&255]&255)<<8) ^ ((S[(r0>>16)&255]&255)<<16) ^ (S[(r1>>24)&255]<<24) ^ KW[r][2];
-        this.C3 = (S[r3&255]&255) ^ ((S[(r0>>8)&255]&255)<<8) ^ ((S[(r1>>16)&255]&255)<<16) ^ (S[(r2>>24)&255]<<24) ^ KW[r][3];
+        this.C0 = (S[r0&255]&255) ^ ((S[(r1>>8)&255]&255)<<8) ^ ((s[(r2>>16)&255]&255)<<16) ^ (s[(r3>>24)&255]<<24) ^ KW[r][0];
+        this.C1 = (s[r1&255]&255) ^ ((S[(r2>>8)&255]&255)<<8) ^ ((S[(r3>>16)&255]&255)<<16) ^ (s[(r0>>24)&255]<<24) ^ KW[r][1];
+        this.C2 = (s[r2&255]&255) ^ ((S[(r3>>8)&255]&255)<<8) ^ ((S[(r0>>16)&255]&255)<<16) ^ (S[(r1>>24)&255]<<24) ^ KW[r][2];
+        this.C3 = (s[r3&255]&255) ^ ((s[(r0>>8)&255]&255)<<8) ^ ((s[(r1>>16)&255]&255)<<16) ^ (S[(r2>>24)&255]<<24) ^ KW[r][3];
     }
 
     private void decryptBlock(int[][] KW)
@@ -610,9 +621,9 @@
         
         // the final round's table is a simple function of Si so we don't use a whole other four tables for it
 
-        this.C0 = (Si[r0&255]&255) ^ ((Si[(r3>>8)&255]&255)<<8) ^ ((Si[(r2>>16)&255]&255)<<16) ^ (Si[(r1>>24)&255]<<24) ^ KW[0][0];
-        this.C1 = (Si[r1&255]&255) ^ ((Si[(r0>>8)&255]&255)<<8) ^ ((Si[(r3>>16)&255]&255)<<16) ^ (Si[(r2>>24)&255]<<24) ^ KW[0][1];
-        this.C2 = (Si[r2&255]&255) ^ ((Si[(r1>>8)&255]&255)<<8) ^ ((Si[(r0>>16)&255]&255)<<16) ^ (Si[(r3>>24)&255]<<24) ^ KW[0][2];
-        this.C3 = (Si[r3&255]&255) ^ ((Si[(r2>>8)&255]&255)<<8) ^ ((Si[(r1>>16)&255]&255)<<16) ^ (Si[(r0>>24)&255]<<24) ^ KW[0][3];
+        this.C0 = (Si[r0&255]&255) ^ ((s[(r3>>8)&255]&255)<<8) ^ ((s[(r2>>16)&255]&255)<<16) ^ (Si[(r1>>24)&255]<<24) ^ KW[0][0];
+        this.C1 = (s[r1&255]&255) ^ ((s[(r0>>8)&255]&255)<<8) ^ ((Si[(r3>>16)&255]&255)<<16) ^ (s[(r2>>24)&255]<<24) ^ KW[0][1];
+        this.C2 = (s[r2&255]&255) ^ ((Si[(r1>>8)&255]&255)<<8) ^ ((Si[(r0>>16)&255]&255)<<16) ^ (s[(r3>>24)&255]<<24) ^ KW[0][2];
+        this.C3 = (Si[r3&255]&255) ^ ((s[(r2>>8)&255]&255)<<8) ^ ((s[(r1>>16)&255]&255)<<16) ^ (s[(r0>>24)&255]<<24) ^ KW[0][3];
     }
 }
```
