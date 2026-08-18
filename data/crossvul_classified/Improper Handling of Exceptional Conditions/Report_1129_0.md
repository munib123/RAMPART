# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in cpp
**Pair ID:** 1129_0
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1129_0`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```cpp
Lines 156-197 of the vulnerable file.

        return SaplingNote(d, addr.get().pk_d, value_, rcm);
    } else {
        return boost::none;
    }
}

boost::optional<SaplingOutgoingPlaintext> SaplingOutgoingPlaintext::decrypt(
    const SaplingOutCiphertext &ciphertext,
    const uint256& ovk,
    const uint256& cv,
    const uint256& cm,
    const uint256& epk
)
{
    auto pt = AttemptSaplingOutDecryption(ciphertext, ovk, cv, cm, epk);
    if (!pt) {
        return boost::none;
    }

    // Deserialize from the plaintext
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << pt.get();

    SaplingOutgoingPlaintext ret;
    ss >> ret;

    assert(ss.size() == 0);

    return ret;
}

boost::optional<SaplingNotePlaintext> SaplingNotePlaintext::decrypt(
    const SaplingEncCiphertext &ciphertext,
    const uint256 &ivk,
    const uint256 &epk,
    const uint256 &cmu
)
{
    auto pt = AttemptSaplingEncDecryption(ciphertext, ivk, epk);
    if (!pt) {
        return boost::none;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -173,15 +173,21 @@
     }
 
     // Deserialize from the plaintext
-    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
-    ss << pt.get();
-
-    SaplingOutgoingPlaintext ret;
-    ss >> ret;
-
-    assert(ss.size() == 0);
-
-    return ret;
+    try {
+        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
+        ss << pt.get();
+
+        SaplingOutgoingPlaintext ret;
+        ss >> ret;
+
+        assert(ss.size() == 0);
+
+        return ret;
+    } catch (const boost::thread_interrupted&) {
+        throw;
+    } catch (...) {
+        return boost::none;
+    }
 }
 
 boost::optional<SaplingNotePlaintext> SaplingNotePlaintext::decrypt(
@@ -197,13 +203,17 @@
     }
 
     // Deserialize from the plaintext
-    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
-    ss << pt.get();
-
     SaplingNotePlaintext ret;
-    ss >> ret;
-
-    assert(ss.size() == 0);
+    try {
+        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
+        ss << pt.get();
+        ss >> ret;
+        assert(ss.size() == 0);
+    } catch (const boost::thread_interrupted&) {
+        throw;
+    } catch (...) {
+        return boost::none;
+    }
 
     uint256 pk_d;
     if (!librustzcash_ivk_to_pkd(ivk.begin(), ret.d.data(), pk_d.begin())) {
@@ -243,11 +253,17 @@
     }
 
     // Deserialize from the plaintext
-    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
-    ss << pt.get();
-
     SaplingNotePlaintext ret;
-    ss >> ret;
+    try {
+        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
+        ss << pt.get();
+        ss >> ret;
+        assert(ss.size() == 0);
+    } catch (const boost::thread_interrupted&) {
+        throw;
+    } catch (...) {
+        return boost::none;
+    }
 
     uint256 cmu_expected;
     if (!librustzcash_sapling_compute_cm(
@@ -265,8 +281,6 @@
         return boost::none;
     }
 
-    assert(ss.size() == 0);
-
     return ret;
 }
 
```
