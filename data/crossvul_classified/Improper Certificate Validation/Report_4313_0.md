# CrossVul Fix Pair: Improper Certificate Validation in java
**Pair ID:** 4313_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4313_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```java
Lines 89-134 of the vulnerable file.


  public static String getDefaultCA() {
    if (UserPreferences.get("viewer", "x509ca") != null)
      return UserPreferences.get("viewer", "x509ca");
    return FileUtils.getVncHomeDir()+"x509_ca.pem";
  }

  public static String getDefaultCRL() {
    if (UserPreferences.get("viewer", "x509crl") != null)
      return UserPreferences.get("viewer", "x509crl");
    return FileUtils.getVncHomeDir()+"x509_crl.pem";
  }

  public static void setDefaults()
  {
    if (new File(getDefaultCA()).exists())
      X509CA.setDefaultStr(getDefaultCA());
    if (new File(getDefaultCRL()).exists())
      X509CRL.setDefaultStr(getDefaultCRL());
  }

// FIXME:
// Need to shutdown the connection cleanly

// FIXME?
// add a finalizer method that calls shutdown

  public boolean processMsg(CConnection cc) {
    is = (FdInStream)cc.getInStream();
    os = (FdOutStream)cc.getOutStream();
    client = cc;

    initGlobal();

    if (manager == null) {
      if (!is.checkNoWait(1))
        return false;

      if (is.readU8() == 0) {
        int result = is.readU32();
        String reason;
        if (result == Security.secResultFailed ||
            result == Security.secResultTooMany)
          reason = is.readString();
        else
          reason = new String("Authentication failure (protocol error)");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,12 +107,6 @@
       X509CRL.setDefaultStr(getDefaultCRL());
   }
 
-// FIXME:
-// Need to shutdown the connection cleanly
-
-// FIXME?
-// add a finalizer method that calls shutdown
-
   public boolean processMsg(CConnection cc) {
     is = (FdInStream)cc.getInStream();
     os = (FdOutStream)cc.getOutStream();
@@ -269,8 +263,13 @@
     {
       Collection<? extends Certificate> certs = null;
       X509Certificate cert = chain[0];
+      String pk =
+        Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded());
       try {
         cert.checkValidity();
+        verifyHostname(cert);
+      } catch(CertificateParsingException e) {
+        throw new SystemException(e.getMessage());
       } catch(CertificateNotYetValidException e) {
         throw new AuthFailureException("server certificate has not been activated");
       } catch(CertificateExpiredException e) {
@@ -279,70 +278,108 @@
 			      "do you want to continue?"))
           throw new AuthFailureException("server certificate has expired");
       }
-      String thumbprint = getThumbprint(cert);
       File vncDir = new File(FileUtils.getVncHomeDir());
-      File certFile = new File(vncDir, "x509_savedcerts.pem");
-      CertificateFactory cf = CertificateFactory.getInstance("X.509");
-      if (vncDir.exists() && certFile.exists() && certFile.canRead()) {
-        InputStream certStream = new MyFileInputStream(certFile);
-        certs = cf.generateCertificates(certStream);
-        for (Certificate c : certs)
-          if (thumbprint.equals(getThumbprint((X509Certificate)c)))
-            return;
-      }
-      try {
-        verifyHostname(cert);
+      if (!vncDir.exists())
+        throw new AuthFailureException("Could not obtain VNC home directory "+
+                                       "path for known hosts storage");
+      File dbPath = new File(vncDir, "x509_known_hosts");
+      String info =
+        "  Subject: "+cert.getSubjectX500Principal().getName()+"\n"+
+        "  Issuer: "+cert.getIssuerX500Principal().getName()+"\n"+
+        "  Serial Number: "+cert.getSerialNumber()+"\n"+
+        "  Version: "+cert.getVersion()+"\n"+
+        "  Signature Algorithm: "+cert.getPublicKey().getAlgorithm()+"\n"+
+        "  Not Valid Before: "+cert.getNotBefore()+"\n"+
+        "  Not Valid After: "+cert.getNotAfter()+"\n"+
+        "  SHA-1 Fingerprint: "+getThumbprint(cert)+"\n";
+      try {
+        if (dbPath.exists()) {
+          FileReader db = new FileReader(dbPath);
+          BufferedReader dbBuf = new BufferedReader(db);
+          String line;
+          String server = client.getServerName().toLowerCase();
+          while ((line = dbBuf.readLine())!=null) {
+            String fields[] = line.split("\\|");
+            if (fields.length==6) {
+              if (server.equals(fields[2]) && pk.equals(fields[5])) {
+                vlog.debug("Server certificate found in known hosts file");
+                dbBuf.close();
+                return;
+              } else if (server.equals(fields[2]) && !pk.equals(fields[5]) ||
+                         !server.equals(fields[2]) && pk.equals(fields[5])) {
+                throw new CertStoreException();
+              }
+            }
+          }
+          dbBuf.close();
+        }
         tm.checkServerTrusted(chain, authType);
+      } catch (IOException e) {
+        throw new AuthFailureException("Could not load known hosts database");
+      } catch (CertStoreException e) {
+        vlog.debug("Server host key mismatch");
+        vlog.debug(info);
+        String text =
+          "This host is previously known with a different "+
+          "certificate, and the new certificate has been "+
+          "signed by an unknown authority\n"+
+          "\n"+info+"\n"+
+          "Someone could be trying to impersonate the site and you should not continue.\n"+
+          "\n"+
+          "Do you want to make an exception for this server?";
+        if (!msg.showMsgBox(YES_NO_OPTION, "Unexpected certificate issuer", text))
+          throw new AuthFailureException("Unexpected certificate issuer");
+        store_pubkey(dbPath, client.getServerName().toLowerCase(), pk);
       } catch (java.lang.Exception e) {
         if (e.getCause() instanceof CertPathBuilderException) {
-          String certinfo =
+          vlog.debug("Server host not previously known");
+          vlog.debug(info);
+          String text =
             "This certificate has been signed by an unknown authority\n"+
+            "\n"+info+"\n"+
+            "Someone could be trying to impersonate the site and you should not continue.\n"+
             "\n"+
-            "  Subject: "+cert.getSubjectX500Principal().getName()+"\n"+
-            "  Issuer: "+cert.getIssuerX500Principal().getName()+"\n"+
-            "  Serial Number: "+cert.getSerialNumber()+"\n"+
-            "  Version: "+cert.getVersion()+"\n"+
-            "  Signature Algorithm: "+cert.getPublicKey().getAlgorithm()+"\n"+
-            "  Not Valid Before: "+cert.getNotBefore()+"\n"+
-            "  Not Valid After: "+cert.getNotAfter()+"\n"+
-            "  SHA1 Fingerprint: "+getThumbprint(cert)+"\n"+
-            "\n"+
-            "Do you want to save it and continue?";
-          if (!msg.showMsgBox(YES_NO_OPTION, "certificate issuer unknown",
-                certinfo)) {
-            throw new AuthFailureException("certificate issuer unknown");
-          }
-          if (certs == null || !certs.contains(cert)) {
-            byte[] der = cert.getEncoded();
-            String pem = Base64.getEncoder().encodeToString(der);
-            pem = pem.replaceAll("(.{64})", "$1\n");
-            FileWriter fw = null;
-            try {
-              if (!vncDir.exists())
-                vncDir.mkdir();
-              if (!certFile.exists() && !certFile.createNewFile()) {
-                vlog.error("Certificate save failed.");
-              } else {
-                fw = new FileWriter(certFile.getAbsolutePath(), true);
-                fw.write("-----BEGIN CERTIFICATE-----\n");
-                fw.write(pem+"\n");
-                fw.write("-----END CERTIFICATE-----\n");
-              }
-            } catch (IOException ioe) {
-              msg.showMsgBox(OK_OPTION, "certificate save failed",
-                             "Could not save the certificate");
-            } finally {
-              try {
-                if (fw != null)
-                  fw.close();
-              } catch(IOException ioe2) {
-                throw new Exception(ioe2.getMessage());
-              }
-            }
-          }
+            "Do you want to make an exception for this server?";
+          if (!msg.showMsgBox(YES_NO_OPTION, "Unknown certificate issuer", text))
+            throw new AuthFailureException("Unknown certificate issuer");
+          store_pubkey(dbPath, client.getServerName().toLowerCase(), pk);
         } else {
           throw new SystemException(e.getMessage());
         }
+      }
+    }
+
+    private void store_pubkey(File dbPath, String serverName, String pk)
+    {
+      ArrayList<String> lines = new ArrayList<String>();
+      File vncDir = new File(FileUtils.getVncHomeDir());
+      try {
+        if (dbPath.exists()) {
+          FileReader db = new FileReader(dbPath);
+          BufferedReader dbBuf = new BufferedReader(db);
+          String line;
+          while ((line = dbBuf.readLine())!=null) {
+            String fields[] = line.split("\\|");
+            if (fields.length==6)
+              if (!serverName.equals(fields[2]) && !pk.equals(fields[5]))
+                lines.add(line);
+          }
+          dbBuf.close();
+        }
+      } catch (IOException e) {
+        throw new AuthFailureException("Could not load known hosts database");
+      }
+      try {
+        if (!dbPath.exists())
+          dbPath.createNewFile();
... (diff truncated)
```
