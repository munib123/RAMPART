# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 3428_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3428_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 117-157 of the vulnerable file.

static ERL_NIF_TERM md5(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM md5_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM md5_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM md5_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM md4(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM md4_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM md4_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM md4_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM md5_mac_n(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha_mac_n(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM des_cbc_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM des_ecb_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM des_ede3_cbc_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM aes_cfb_128_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM aes_ctr_encrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rand_bytes_1(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rand_bytes_3(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rand_uniform_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM mod_exp_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM dss_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rsa_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM aes_cbc_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM exor(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rc4_encrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rc4_set_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rc4_encrypt_with_state(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rc2_40_cbc_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rsa_sign_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM dss_sign_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rsa_public_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rsa_private_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM dh_generate_parameters_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM dh_check(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM dh_generate_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM dh_compute_key_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM bf_cfb64_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM bf_cbc_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,7 +134,9 @@
 static ERL_NIF_TERM aes_cfb_128_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
 static ERL_NIF_TERM aes_ctr_encrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
 static ERL_NIF_TERM rand_bytes_1(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
+static ERL_NIF_TERM strong_rand_bytes_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
 static ERL_NIF_TERM rand_bytes_3(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
+static ERL_NIF_TERM strong_rand_mpint_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
 static ERL_NIF_TERM rand_uniform_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
 static ERL_NIF_TERM mod_exp_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
 static ERL_NIF_TERM dss_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
@@ -204,7 +206,9 @@
     {"aes_ctr_encrypt", 3, aes_ctr_encrypt},
     {"aes_ctr_decrypt", 3, aes_ctr_encrypt},
     {"rand_bytes", 1, rand_bytes_1},
+    {"strong_rand_bytes_nif", 1, strong_rand_bytes_nif},
     {"rand_bytes", 3, rand_bytes_3},
+    {"strong_rand_mpint_nif", 3, strong_rand_mpint_nif},
     {"rand_uniform_nif", 2, rand_uniform_nif},
     {"mod_exp_nif", 3, mod_exp_nif},
     {"dss_verify", 4, dss_verify},
@@ -704,6 +708,22 @@
     ERL_VALGRIND_MAKE_MEM_DEFINED(data, bytes);
     return ret;
 }
+static ERL_NIF_TERM strong_rand_bytes_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
+{/* (Bytes) */     
+    unsigned bytes;
+    unsigned char* data;
+    ERL_NIF_TERM ret;
+    if (!enif_get_uint(env, argv[0], &bytes)) {
+	return enif_make_badarg(env);
+    }
+    data = enif_make_new_binary(env, bytes, &ret);
+    if ( RAND_bytes(data, bytes) != 1) {
+        return atom_false;
+    }
+    ERL_VALGRIND_MAKE_MEM_DEFINED(data, bytes);
+    return ret;
+}
+
 static ERL_NIF_TERM rand_bytes_3(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
 {/* (Bytes, TopMask, BottomMask) */    
     unsigned bytes;
@@ -722,6 +742,47 @@
 	data[bytes-1] |= top_mask;
 	data[0] |= bot_mask;
     }
+    return ret;
+}
+static ERL_NIF_TERM strong_rand_mpint_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
+{/* (Bytes, TopMask, BottomMask) */    
+    unsigned bits;
+    BIGNUM *bn_rand;
+    int top, bottom;
+    unsigned char* data;
+    unsigned dlen;
+    ERL_NIF_TERM ret;
+    if (!enif_get_uint(env, argv[0], &bits)
+	|| !enif_get_int(env, argv[1], &top)
+	|| !enif_get_int(env, argv[2], &bottom)) {
+	return enif_make_badarg(env);
+    }
+    if (! (top == -1 || top == 0 || top == 1) ) {
+        return enif_make_badarg(env);
+    }
+    if (! (bottom == 0 || bottom == 1) ) {
+        return enif_make_badarg(env);
+    }
+
+    bn_rand = BN_new();
+    if (! bn_rand ) {
+        return enif_make_badarg(env);
+    }
+
+    /* Get a (bits) bit random number */
+    if (!BN_rand(bn_rand, bits, top, bottom)) {
+        ret = atom_false;
+    }
+    else {
+	/* Copy the bignum into an erlang mpint binary. */
+	dlen = BN_num_bytes(bn_rand);
+	data = enif_make_new_binary(env, dlen+4, &ret);
+	put_int32(data, dlen);
+	BN_bn2bin(bn_rand, data+4);
+	ERL_VALGRIND_MAKE_MEM_DEFINED(data+4, dlen);
+    }
+    BN_free(bn_rand);
+
     return ret;
 }
 
```
