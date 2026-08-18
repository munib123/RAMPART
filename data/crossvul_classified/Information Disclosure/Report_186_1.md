# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 186_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `186_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 57-97 of the vulnerable file.

*/
bool DSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(!DL_Scheme_PrivateKey::check_key(rng, strong) || m_x >= group_q())
      return false;

   if(!strong)
      return true;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
   }

namespace {

/**
* Object that can create a DSA signature
*/
class DSA_Signature_Operation final : public PK_Ops::Signature_with_EMSA
   {
   public:
      DSA_Signature_Operation(const DSA_PrivateKey& dsa, const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_group(dsa.get_group()),
         m_x(dsa.get_x()),
         m_mod_q(dsa.group_q())
         {
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
         m_rfc6979_hash = hash_for_emsa(emsa);
#endif
         }

      size_t max_input_bits() const override { return m_group.get_q().bits(); }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                   RandomNumberGenerator& rng) override;
   private:
      const DL_Group m_group;
      const BigInt& m_x;
      Modular_Reducer m_mod_q;
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
      std::string m_rfc6979_hash;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,7 +74,9 @@
 class DSA_Signature_Operation final : public PK_Ops::Signature_with_EMSA
    {
    public:
-      DSA_Signature_Operation(const DSA_PrivateKey& dsa, const std::string& emsa) :
+      DSA_Signature_Operation(const DSA_PrivateKey& dsa,
+                              const std::string& emsa,
+                              RandomNumberGenerator& rng) :
          PK_Ops::Signature_with_EMSA(emsa),
          m_group(dsa.get_group()),
          m_x(dsa.get_x()),
@@ -83,6 +85,9 @@
 #if defined(BOTAN_HAS_RFC6979_GENERATOR)
          m_rfc6979_hash = hash_for_emsa(emsa);
 #endif
+
+         m_b = BigInt::random_integer(rng, 2, dsa.group_q());
+         m_b_inv = inverse_mod(m_b, dsa.group_q());
          }
 
       size_t max_input_bits() const override { return m_group.get_q().bits(); }
@@ -96,6 +101,8 @@
 #if defined(BOTAN_HAS_RFC6979_GENERATOR)
       std::string m_rfc6979_hash;
 #endif
+
+      BigInt m_b, m_b_inv;
    };
 
 secure_vector<uint8_t>
@@ -104,22 +111,32 @@
    {
    const BigInt& q = m_group.get_q();
 
-   BigInt i(msg, msg_len, q.bits());
-
-   while(i >= q)
-      i -= q;
+   BigInt m(msg, msg_len, q.bits());
+
+   while(m >= q)
+      m -= q;
 
 #if defined(BOTAN_HAS_RFC6979_GENERATOR)
    BOTAN_UNUSED(rng);
-   const BigInt k = generate_rfc6979_nonce(m_x, q, i, m_rfc6979_hash);
+   const BigInt k = generate_rfc6979_nonce(m_x, q, m, m_rfc6979_hash);
 #else
    const BigInt k = BigInt::random_integer(rng, 1, q);
 #endif
 
-   BigInt s = inverse_mod(k, q);
+   const BigInt k_inv = inverse_mod(k, q);
+
    const BigInt r = m_mod_q.reduce(m_group.power_g_p(k));
 
-   s = m_mod_q.multiply(s, mul_add(m_x, r, i));
+   /*
+   * Blind the input message and compute x*r+m as (x*r*b + m*b)/b
+   */
+   m_b = m_mod_q.square(m_b);
+   m_b_inv = m_mod_q.square(m_b_inv);
+
+   m = m_mod_q.multiply(m_b, m);
+   const BigInt xr = m_mod_q.multiply(m_mod_q.multiply(m_x, m_b), r);
+
+   const BigInt s = m_mod_q.multiply(m_b_inv, m_mod_q.multiply(k_inv, xr + m));
 
    // With overwhelming probability, a bug rather than actual zero r/s
    if(r.is_zero() || s.is_zero())
@@ -140,7 +157,8 @@
          m_group(dsa.get_group()),
          m_y(dsa.get_y()),
          m_mod_q(dsa.group_q())
-         {}
+         {
+         }
 
       size_t max_input_bits() const override { return m_group.get_q().bits(); }
 
@@ -193,12 +211,12 @@
    }
 
 std::unique_ptr<PK_Ops::Signature>
-DSA_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
+DSA_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                     const std::string& params,
                                     const std::string& provider) const
    {
    if(provider == "base" || provider.empty())
-      return std::unique_ptr<PK_Ops::Signature>(new DSA_Signature_Operation(*this, params));
+      return std::unique_ptr<PK_Ops::Signature>(new DSA_Signature_Operation(*this, params, rng));
    throw Provider_Not_Found(algo_name(), provider);
    }
 
```
