# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 186_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `186_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 34-74 of the vulnerable file.

   {
   if(!public_point().on_the_curve())
      return false;

   if(!strong)
      return true;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
   }

namespace {

/**
* ECDSA signature operation
*/
class ECDSA_Signature_Operation final : public PK_Ops::Signature_with_EMSA
   {
   public:

      ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa,
                                const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_group(ecdsa.domain()),
         m_x(ecdsa.private_value())
         {
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
         m_rfc6979_hash = hash_for_emsa(emsa);
#endif
         }

      size_t max_input_bits() const override { return m_group.get_order_bits(); }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                      RandomNumberGenerator& rng) override;

   private:
      const EC_Group m_group;
      const BigInt& m_x;

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
      std::string m_rfc6979_hash;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,8 @@
    public:
 
       ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa,
-                                const std::string& emsa) :
+                                const std::string& emsa,
+                                RandomNumberGenerator& rng) :
          PK_Ops::Signature_with_EMSA(emsa),
          m_group(ecdsa.domain()),
          m_x(ecdsa.private_value())
@@ -59,6 +60,9 @@
 #if defined(BOTAN_HAS_RFC6979_GENERATOR)
          m_rfc6979_hash = hash_for_emsa(emsa);
 #endif
+
+         m_b = m_group.random_scalar(rng);
+         m_b_inv = m_group.inverse_mod_order(m_b);
          }
 
       size_t max_input_bits() const override { return m_group.get_order_bits(); }
@@ -75,6 +79,8 @@
 #endif
 
       std::vector<BigInt> m_ws;
+
+      BigInt m_b, m_b_inv;
    };
 
 secure_vector<uint8_t>
@@ -89,12 +95,21 @@
    const BigInt k = m_group.random_scalar(rng);
 #endif
 
-   const BigInt k_inv = m_group.inverse_mod_order(k);
    const BigInt r = m_group.mod_order(
       m_group.blinded_base_point_multiply_x(k, rng, m_ws));
 
-   const BigInt xrm = m_group.mod_order(m_group.multiply_mod_order(m_x, r) + m);
-   const BigInt s = m_group.multiply_mod_order(k_inv, xrm);
+   const BigInt k_inv = m_group.inverse_mod_order(k);
+
+   /*
+   * Blind the input message and compute x*r+m as (x*r*b + m*b)/b
+   */
+   m_b = m_group.square_mod_order(m_b);
+   m_b_inv = m_group.square_mod_order(m_b_inv);
+
+   m = m_group.multiply_mod_order(m_b, m);
+   const BigInt xr = m_group.multiply_mod_order(m_x, m_b, r);
+
+   const BigInt s = m_group.multiply_mod_order(k_inv, xr + m, m_b_inv);
 
    // With overwhelming probability, a bug rather than actual zero r/s
    if(r.is_zero() || s.is_zero())
@@ -144,7 +159,7 @@
 
    const BigInt w = m_group.inverse_mod_order(s);
 
-   const BigInt u1 = m_group.multiply_mod_order(e, w);
+   const BigInt u1 = m_group.multiply_mod_order(m_group.mod_order(e), w);
    const BigInt u2 = m_group.multiply_mod_order(r, w);
    const PointGFp R = m_gy_mul.multi_exp(u1, u2);
 
@@ -198,7 +213,7 @@
    }
 
 std::unique_ptr<PK_Ops::Signature>
-ECDSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
+ECDSA_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                       const std::string& params,
                                       const std::string& provider) const
    {
@@ -233,7 +248,7 @@
 #endif
 
    if(provider == "base" || provider.empty())
-      return std::unique_ptr<PK_Ops::Signature>(new ECDSA_Signature_Operation(*this, params));
+      return std::unique_ptr<PK_Ops::Signature>(new ECDSA_Signature_Operation(*this, params, rng));
 
    throw Provider_Not_Found(algo_name(), provider);
    }
```
