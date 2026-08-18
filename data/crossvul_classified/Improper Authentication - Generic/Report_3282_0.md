# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 3282_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3282_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 9-49 of the vulnerable file.

try:
    import ctypes
    lib = ctypes.LibraryLoader(ctypes.CDLL).LoadLibrary('soft-pkcs11.so')
    del lib
    have_soft_pkcs11 = True
except:
    have_soft_pkcs11 = False

# Construct a krb5.conf fragment configuring pkinit.
certs = os.path.join(srctop, 'tests', 'dejagnu', 'pkinit-certs')
ca_pem = os.path.join(certs, 'ca.pem')
kdc_pem = os.path.join(certs, 'kdc.pem')
user_pem = os.path.join(certs, 'user.pem')
privkey_pem = os.path.join(certs, 'privkey.pem')
privkey_enc_pem = os.path.join(certs, 'privkey-enc.pem')
user_p12 = os.path.join(certs, 'user.p12')
user_enc_p12 = os.path.join(certs, 'user-enc.p12')
user_upn_p12 = os.path.join(certs, 'user-upn.p12')
user_upn2_p12 = os.path.join(certs, 'user-upn2.p12')
user_upn3_p12 = os.path.join(certs, 'user-upn3.p12')
path = os.path.join(os.getcwd(), 'testdir', 'tmp-pkinit-certs')
path_enc = os.path.join(os.getcwd(), 'testdir', 'tmp-pkinit-certs-enc')

pkinit_krb5_conf = {'realms': {'$realm': {
            'pkinit_anchors': 'FILE:%s' % ca_pem}}}
pkinit_kdc_conf = {'realms': {'$realm': {
            'default_principal_flags': '+preauth',
            'pkinit_eku_checking': 'none',
            'pkinit_identity': 'FILE:%s,%s' % (kdc_pem, privkey_pem),
            'pkinit_indicator': ['indpkinit1', 'indpkinit2']}}}
restrictive_kdc_conf = {'realms': {'$realm': {
            'restrict_anonymous_to_tgt': 'true' }}}

testprincs = {'krbtgt/KRBTEST.COM': {'keys': 'aes128-cts'},
              'user': {'keys': 'aes128-cts', 'flags': '+preauth'},
              'user2': {'keys': 'aes128-cts', 'flags': '+preauth'}}
alias_kdc_conf = {'realms': {'$realm': {
            'default_principal_flags': '+preauth',
            'pkinit_eku_checking': 'none',
            'pkinit_allow_upn': 'true',
            'pkinit_identity': 'FILE:%s,%s' % (kdc_pem, privkey_pem),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,7 @@
 user_upn_p12 = os.path.join(certs, 'user-upn.p12')
 user_upn2_p12 = os.path.join(certs, 'user-upn2.p12')
 user_upn3_p12 = os.path.join(certs, 'user-upn3.p12')
+generic_p12 = os.path.join(certs, 'generic.p12')
 path = os.path.join(os.getcwd(), 'testdir', 'tmp-pkinit-certs')
 path_enc = os.path.join(os.getcwd(), 'testdir', 'tmp-pkinit-certs-enc')
 
@@ -65,6 +66,7 @@
 p12_upn_identity = 'PKCS12:%s' % user_upn_p12
 p12_upn2_identity = 'PKCS12:%s' % user_upn2_p12
 p12_upn3_identity = 'PKCS12:%s' % user_upn3_p12
+p12_generic_identity = 'PKCS12:%s' % generic_p12
 p12_enc_identity = 'PKCS12:%s' % user_enc_p12
 p11_identity = 'PKCS11:soft-pkcs11.so'
 p11_token_identity = ('PKCS11:module_name=soft-pkcs11.so:'
@@ -329,6 +331,14 @@
             flags=['-X', 'X509_user_identity=%s' % p12_identity],
             expected_code=1, expected_msg=msg)
 
+# Authorize a client cert with no PKINIT extensions using subject and
+# issuer.  (Relies on EKU checking being turned off.)
+rule = '&&<SUBJECT>CN=user$<ISSUER>O=MIT,'
+realm.run([kadminl, 'setstr', realm.user_princ, 'pkinit_cert_match', rule])
+realm.kinit(realm.user_princ,
+            flags=['-X', 'X509_user_identity=%s' % p12_generic_identity])
+realm.klist(realm.user_princ)
+
 if not have_soft_pkcs11:
     skip_rest('PKINIT PKCS11 tests', 'soft-pkcs11.so not found')
 
```
