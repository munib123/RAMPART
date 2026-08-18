# CrossVul Fix Pair: Improper Authentication in shell
**Pair ID:** 3280_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3280_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```bash
Lines 147-168 of the vulnerable file.

    -out user-upn.pem -in user-upn.csr
openssl pkcs12 -export -in user-upn.pem -inkey privkey.pem -out user-upn.p12 \
    -passout pass:

SUBJECT=user openssl req -config openssl.cnf -new -subj /CN=user \
    -key privkey.pem -out user-upn2.csr
SUBJECT=user openssl x509 -extfile openssl.cnf -extensions exts_upn2_client \
    -set_serial 5 -days $DAYS -req -CA ca.pem -CAkey privkey.pem \
    -out user-upn2.pem -in user-upn2.csr
openssl pkcs12 -export -in user-upn2.pem -inkey privkey.pem \
     -out user-upn2.p12 -passout pass:

SUBJECT=user openssl req -config openssl.cnf -new -subj /CN=user \
    -key privkey.pem -out user-upn3.csr
SUBJECT=user openssl x509 -extfile openssl.cnf -extensions exts_upn3_client \
    -set_serial 6 -days $DAYS -req -CA ca.pem -CAkey privkey.pem \
    -out user-upn3.pem -in user-upn3.csr
openssl pkcs12 -export -in user-upn3.pem -inkey privkey.pem \
     -out user-upn3.p12 -passout pass:

# Clean up.
rm -f openssl.cnf kdc.csr user.csr user-upn.csr user-upn2.csr user-upn3.csr
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -164,5 +164,14 @@
 openssl pkcs12 -export -in user-upn3.pem -inkey privkey.pem \
      -out user-upn3.p12 -passout pass:
 
+# Generate a client certificate and PKCS#12 bundle with no PKINIT extensions.
+SUBJECT=user openssl req -config openssl.cnf -new -subj /CN=user \
+    -key privkey.pem -out generic.csr
+SUBJECT=user openssl x509 -set_serial 7 -days $DAYS -req -CA ca.pem \
+    -CAkey privkey.pem -out generic.pem -in generic.csr
+openssl pkcs12 -export -in generic.pem -inkey privkey.pem -out generic.p12 \
+    -passout pass:
+
 # Clean up.
 rm -f openssl.cnf kdc.csr user.csr user-upn.csr user-upn2.csr user-upn3.csr
+rm -f generic.csr
```
