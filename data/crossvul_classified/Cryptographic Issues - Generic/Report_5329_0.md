# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5329_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5329_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 19-59 of the vulnerable file.

} while (0)
#define GetCipherInit(obj, ctx) do { \
    TypedData_Get_Struct((obj), EVP_CIPHER_CTX, &ossl_cipher_type, (ctx)); \
} while (0)
#define GetCipher(obj, ctx) do { \
    GetCipherInit((obj), (ctx)); \
    if (!(ctx)) { \
	ossl_raise(rb_eRuntimeError, "Cipher not inititalized!"); \
    } \
} while (0)
#define SafeGetCipher(obj, ctx) do { \
    OSSL_Check_Kind((obj), cCipher); \
    GetCipher((obj), (ctx)); \
} while (0)

/*
 * Classes
 */
VALUE cCipher;
VALUE eCipherError;
static ID id_auth_tag_len;

static VALUE ossl_cipher_alloc(VALUE klass);
static void ossl_cipher_free(void *ptr);

static const rb_data_type_t ossl_cipher_type = {
    "OpenSSL/Cipher",
    {
	0, ossl_cipher_free,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY,
};

/*
 * PUBLIC
 */
const EVP_CIPHER *
GetCipherPtr(VALUE obj)
{
    if (rb_obj_is_kind_of(obj, cCipher)) {
	EVP_CIPHER_CTX *ctx;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,7 +36,7 @@
  */
 VALUE cCipher;
 VALUE eCipherError;
-static ID id_auth_tag_len;
+static ID id_auth_tag_len, id_key_set;
 
 static VALUE ossl_cipher_alloc(VALUE klass);
 static void ossl_cipher_free(void *ptr);
@@ -118,7 +118,6 @@
     EVP_CIPHER_CTX *ctx;
     const EVP_CIPHER *cipher;
     char *name;
-    unsigned char dummy_key[EVP_MAX_KEY_LENGTH] = { 0 };
 
     name = StringValueCStr(str);
     GetCipherInit(self, ctx);
@@ -129,16 +128,7 @@
     if (!(cipher = EVP_get_cipherbyname(name))) {
 	ossl_raise(rb_eRuntimeError, "unsupported cipher algorithm (%"PRIsVALUE")", str);
     }
-    /*
-     * EVP_CipherInit_ex() allows to specify NULL to key and IV, however some
-     * ciphers don't handle well (OpenSSL's bug). [Bug #2768]
-     *
-     * The EVP which has EVP_CIPH_RAND_KEY flag (such as DES3) allows
-     * uninitialized key, but other EVPs (such as AES) does not allow it.
-     * Calling EVP_CipherUpdate() without initializing key causes SEGV so we
-     * set the data filled with "\0" as the key by default.
-     */
-    if (EVP_CipherInit_ex(ctx, cipher, NULL, dummy_key, NULL, -1) != 1)
+    if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, -1) != 1)
 	ossl_raise(eCipherError, NULL);
 
     return self;
@@ -251,6 +241,9 @@
 	ossl_raise(eCipherError, NULL);
     }
 
+    if (p_key)
+	rb_ivar_set(self, id_key_set, Qtrue);
+
     return self;
 }
 
@@ -337,6 +330,8 @@
     OPENSSL_cleanse(key, sizeof key);
     OPENSSL_cleanse(iv, sizeof iv);
 
+    rb_ivar_set(self, id_key_set, Qtrue);
+
     return Qnil;
 }
 
@@ -386,6 +381,9 @@
     VALUE data, str;
 
     rb_scan_args(argc, argv, "11", &data, &str);
+
+    if (!RTEST(rb_attr_get(self, id_key_set)))
+	ossl_raise(eCipherError, "key not set");
 
     StringValue(data);
     in = (unsigned char *)RSTRING_PTR(data);
@@ -487,6 +485,8 @@
 
     if (EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char *)RSTRING_PTR(key), NULL, -1) != 1)
 	ossl_raise(eCipherError, NULL);
+
+    rb_ivar_set(self, id_key_set, Qtrue);
 
     return key;
 }
@@ -1082,4 +1082,5 @@
     rb_define_method(cCipher, "padding=", ossl_cipher_set_padding, 1);
 
     id_auth_tag_len = rb_intern_const("auth_tag_len");
-}
+    id_key_set = rb_intern_const("key_set");
+}
```
