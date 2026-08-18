# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4938_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4938_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 23-65 of the vulnerable file.

    char *hex;

    num_bn = BN_new();
    if (num_bn == NULL)
        return -1;
    ASN1_INTEGER_to_BN(num, num_bn);
    if ((hex = BN_bn2hex(num_bn))) {
        result = BIO_write(bio, "0x", 2) > 0;
        result = result && BIO_write(bio, hex, strlen(hex)) > 0;
        OPENSSL_free(hex);
    }
    BN_free(num_bn);

    return result;
}

int TS_OBJ_print_bio(BIO *bio, const ASN1_OBJECT *obj)
{
    char obj_txt[128];

    int len = OBJ_obj2txt(obj_txt, sizeof(obj_txt), obj, 0);
    BIO_write(bio, obj_txt, len);
    BIO_write(bio, "\n", 1);

    return 1;
}

int TS_ext_print_bio(BIO *bio, const STACK_OF(X509_EXTENSION) *extensions)
{
    int i, critical, n;
    X509_EXTENSION *ex;
    ASN1_OBJECT *obj;

    BIO_printf(bio, "Extensions:\n");
    n = X509v3_get_ext_count(extensions);
    for (i = 0; i < n; i++) {
        ex = X509v3_get_ext(extensions, i);
        obj = X509_EXTENSION_get_object(ex);
        i2a_ASN1_OBJECT(bio, obj);
        critical = X509_EXTENSION_get_critical(ex);
        BIO_printf(bio, ": %s\n", critical ? "critical" : "");
        if (!X509V3_EXT_print(bio, ex, 0, 4)) {
            BIO_printf(bio, "%4s", "");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,9 +40,8 @@
 {
     char obj_txt[128];
 
-    int len = OBJ_obj2txt(obj_txt, sizeof(obj_txt), obj, 0);
-    BIO_write(bio, obj_txt, len);
-    BIO_write(bio, "\n", 1);
+    OBJ_obj2txt(obj_txt, sizeof(obj_txt), obj, 0);
+    BIO_printf(bio, "%s\n", obj_txt);
 
     return 1;
 }
```
