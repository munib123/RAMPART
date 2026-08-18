# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 186_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `186_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 187-227 of the vulnerable file.

      */
      const BigInt& get_g_y() const;

      /**
      * Return the order of the base point
      * @result order of the base point
      */
      const BigInt& get_order() const;

      /*
      * Reduce x modulo the order
      */
      BigInt mod_order(const BigInt& x) const;

      /*
      * Return inverse of x modulo the order
      */
      BigInt inverse_mod_order(const BigInt& x) const;

      /*
      * Reduce (x*y) modulo the order
      */
      BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const;

      /**
      * Return the cofactor
      * @result the cofactor
      */
      const BigInt& get_cofactor() const;

      /**
      * Check if y is a plausible point on the curve
      *
      * In particular, checks that it is a point on the curve, not infinity,
      * and that it has order matching the group.
      */
      bool verify_public_element(const PointGFp& y) const;

      /**
      * Return the OID of these domain parameters
      * @result the OID as a string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -204,9 +204,19 @@
       BigInt inverse_mod_order(const BigInt& x) const;
 
       /*
+      * Reduce (x*x) modulo the order
+      */
+      BigInt square_mod_order(const BigInt& x) const;
+
+      /*
       * Reduce (x*y) modulo the order
       */
       BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const;
+
+      /*
+      * Reduce (x*y*z) modulo the order
+      */
+      BigInt multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const;
 
       /**
       * Return the cofactor
```
