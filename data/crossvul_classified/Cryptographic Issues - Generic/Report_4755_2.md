# CrossVul Fix Pair: Cryptographic Issues in java
**Pair ID:** 4755_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4755_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```java
Lines 1-39 of the vulnerable file.

package org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.DHDomainParameters;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;

public class BCDHPublicKey
    implements DHPublicKey
{
    static final long serialVersionUID = -216691575254424324L;
    
    private BigInteger              y;

    private transient DHParameterSpec         dhSpec;
    private transient SubjectPublicKeyInfo    info;
    
    BCDHPublicKey(
        DHPublicKeySpec spec)
    {
        this.y = spec.getY();
        this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,10 +16,12 @@
 import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
 import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
 import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
-import org.bouncycastle.asn1.x9.DHDomainParameters;
 import org.bouncycastle.asn1.x9.DomainParameters;
+import org.bouncycastle.asn1.x9.ValidationParams;
 import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
+import org.bouncycastle.crypto.params.DHParameters;
 import org.bouncycastle.crypto.params.DHPublicKeyParameters;
+import org.bouncycastle.crypto.params.DHValidationParameters;
 import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
 
 public class BCDHPublicKey
@@ -29,6 +31,7 @@
     
     private BigInteger              y;
 
+    private transient DHPublicKeyParameters   dhPublicKey;
     private transient DHParameterSpec         dhSpec;
     private transient SubjectPublicKeyInfo    info;
     
@@ -37,6 +40,7 @@
     {
         this.y = spec.getY();
         this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
+        this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(spec.getP(), spec.getG()));
     }
 
     BCDHPublicKey(
@@ -44,6 +48,7 @@
     {
         this.y = key.getY();
         this.dhSpec = key.getParams();
+        this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
     }
 
     BCDHPublicKey(
@@ -51,6 +56,7 @@
     {
         this.y = params.getY();
         this.dhSpec = new DHParameterSpec(params.getParameters().getP(), params.getParameters().getG(), params.getParameters().getL());
+        this.dhPublicKey = params;
     }
 
     BCDHPublicKey(
@@ -59,6 +65,7 @@
     {
         this.y = y;
         this.dhSpec = dhSpec;
+        this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
     }
 
     public BCDHPublicKey(
@@ -94,12 +101,23 @@
             {
                 this.dhSpec = new DHParameterSpec(params.getP(), params.getG());
             }
+            this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
         }
         else if (id.equals(X9ObjectIdentifiers.dhpublicnumber))
         {
             DomainParameters params = DomainParameters.getInstance(seq);
 
             this.dhSpec = new DHParameterSpec(params.getP(), params.getG());
+            ValidationParams validationParams = params.getValidationParams();
+            if (validationParams != null)
+            {
+                this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(params.getP(), params.getG(), params.getQ(), params.getJ(),
+                                            new DHValidationParameters(validationParams.getSeed(), validationParams.getPgenCounter().intValue())));
+            }
+            else
+            {
+                this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(params.getP(), params.getG(), params.getQ(), params.getJ(), null));
+            }
         }
         else
         {
@@ -135,6 +153,11 @@
     public BigInteger getY()
     {
         return y;
+    }
+
+    public DHPublicKeyParameters engineGetKeyParameters()
+    {
+        return dhPublicKey;
     }
 
     private boolean isPKCSParam(ASN1Sequence seq)
```
