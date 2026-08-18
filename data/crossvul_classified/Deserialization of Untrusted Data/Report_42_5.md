# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 42_5
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `42_5`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 138-187 of the vulnerable file.

    /**
     * Computes the fieldpolynomial. This can take a long time for big degrees.
     */
    protected abstract void computeFieldPolynomial();

    /**
     * Inverts the given matrix represented as bitstrings.
     *
     * @param matrix the matrix to invert as a Bitstring[]
     * @return matrix^(-1)
     */
    protected final GF2Polynomial[] invertMatrix(GF2Polynomial[] matrix)
    {
        GF2Polynomial[] a = new GF2Polynomial[matrix.length];
        GF2Polynomial[] inv = new GF2Polynomial[matrix.length];
        GF2Polynomial dummy;
        int i, j;
        // initialize a as a copy of matrix and inv as E(inheitsmatrix)
        for (i = 0; i < mDegree; i++)
        {
            try
            {
                a[i] = new GF2Polynomial(matrix[i]);
                inv[i] = new GF2Polynomial(mDegree);
                inv[i].setBit(mDegree - 1 - i);
            }
            catch (RuntimeException BDNEExc)
            {
                BDNEExc.printStackTrace();
            }
        }
        // construct triangle matrix so that for each a[i] the first i bits are
        // zero
        for (i = 0; i < mDegree - 1; i++)
        {
            // find column where bit i is set
            j = i;
            while ((j < mDegree) && !a[j].testBit(mDegree - 1 - i))
            {
                j++;
            }
            if (j >= mDegree)
            {
                throw new RuntimeException(
                    "GF2nField.invertMatrix: Matrix cannot be inverted!");
            }
            if (i != j)
            { // swap a[i]/a[j] and inv[i]/inv[j]
                dummy = a[i];
                a[i] = a[j];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,16 +155,9 @@
         // initialize a as a copy of matrix and inv as E(inheitsmatrix)
         for (i = 0; i < mDegree; i++)
         {
-            try
-            {
-                a[i] = new GF2Polynomial(matrix[i]);
-                inv[i] = new GF2Polynomial(mDegree);
-                inv[i].setBit(mDegree - 1 - i);
-            }
-            catch (RuntimeException BDNEExc)
-            {
-                BDNEExc.printStackTrace();
-            }
+            a[i] = new GF2Polynomial(matrix[i]);
+            inv[i] = new GF2Polynomial(mDegree);
+            inv[i].setBit(mDegree - 1 - i);
         }
         // construct triangle matrix so that for each a[i] the first i bits are
         // zero
```
