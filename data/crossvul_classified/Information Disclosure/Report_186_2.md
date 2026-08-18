# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 186_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `186_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 67-107 of the vulnerable file.

      const BigInt& b() const { return m_curve.get_b(); }
      const BigInt& order() const { return m_order; }
      const BigInt& cofactor() const { return m_cofactor; }
      const BigInt& g_x() const { return m_g_x; }
      const BigInt& g_y() const { return m_g_y; }

      size_t p_bits() const { return m_p_bits; }
      size_t p_bytes() const { return (m_p_bits + 7) / 8; }

      size_t order_bits() const { return m_order_bits; }
      size_t order_bytes() const { return (m_order_bits + 7) / 8; }

      const CurveGFp& curve() const { return m_curve; }
      const PointGFp& base_point() const { return m_base_point; }

      bool a_is_minus_3() const { return m_a_is_minus_3; }
      bool a_is_zero() const { return m_a_is_zero; }

      BigInt mod_order(const BigInt& x) const { return m_mod_order.reduce(x); }

      BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const
         {
         return m_mod_order.multiply(x, y);
         }

      BigInt inverse_mod_order(const BigInt& x) const
         {
         return inverse_mod(x, m_order);
         }

      PointGFp blinded_base_point_multiply(const BigInt& k,
                                           RandomNumberGenerator& rng,
                                           std::vector<BigInt>& ws) const
         {
         return m_base_mult.mul(k, rng, m_order, ws);
         }

   private:
      CurveGFp m_curve;
      PointGFp m_base_point;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,9 +84,19 @@
 
       BigInt mod_order(const BigInt& x) const { return m_mod_order.reduce(x); }
 
+      BigInt square_mod_order(const BigInt& x) const
+         {
+         return m_mod_order.square(x);
+         }
+
       BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const
          {
          return m_mod_order.multiply(x, y);
+         }
+
+      BigInt multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const
+         {
+         return m_mod_order.multiply(m_mod_order.multiply(x, y), z);
          }
 
       BigInt inverse_mod_order(const BigInt& x) const
@@ -477,9 +487,19 @@
    return data().mod_order(k);
    }
 
+BigInt EC_Group::square_mod_order(const BigInt& x) const
+   {
+   return data().square_mod_order(x);
+   }
+
 BigInt EC_Group::multiply_mod_order(const BigInt& x, const BigInt& y) const
    {
    return data().multiply_mod_order(x, y);
+   }
+
+BigInt EC_Group::multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const
+   {
+   return data().multiply_mod_order(x, y, z);
    }
 
 BigInt EC_Group::inverse_mod_order(const BigInt& x) const
```
