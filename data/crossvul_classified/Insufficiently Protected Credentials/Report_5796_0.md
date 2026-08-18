# CrossVul Fix Pair: Credentials Management Errors in java
**Pair ID:** 5796_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5796_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```java
Lines 1491-1531 of the vulnerable file.

             */
            private static final long serialVersionUID = -3707951427730113110L;

            /**
             * @param kind
             *      One of the constants defined in {@link ISVNAuthenticationManager},
             *      indicating what subtype of {@link SVNAuthentication} is expected.
             */
            public abstract SVNAuthentication createSVNAuthentication(String kind) throws SVNException;
        }

        /**
         * Username/password based authentication.
         */
        public static final class PasswordCredential extends Credential {
            /**
             * 
             */
            private static final long serialVersionUID = -1676145651108866745L;
            private final String userName;
            private final String password; // scrambled by base64

            public PasswordCredential(String userName, String password) {
                this.userName = userName;
                this.password = Scrambler.scramble(password);
            }

            @Override
            public SVNAuthentication createSVNAuthentication(String kind) {
                if(kind.equals(ISVNAuthenticationManager.SSH))
                    return new SVNSSHAuthentication(userName,Scrambler.descramble(password),-1,false);
                else
                    return new SVNPasswordAuthentication(userName,Scrambler.descramble(password),false);
            }
        }

        /**
         * Public key authentication for Subversion over SSH.
         */
        public static final class SshPublicKeyCredential extends Credential {
            /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1508,19 +1508,23 @@
              */
             private static final long serialVersionUID = -1676145651108866745L;
             private final String userName;
-            private final String password; // scrambled by base64
+            private final Secret password; // for historical reasons, scrambled by base64 in addition to using 'Secret'
 
             public PasswordCredential(String userName, String password) {
                 this.userName = userName;
-                this.password = Scrambler.scramble(password);
+                this.password = Secret.fromString(Scrambler.scramble(password));
             }
 
             @Override
             public SVNAuthentication createSVNAuthentication(String kind) {
                 if(kind.equals(ISVNAuthenticationManager.SSH))
-                    return new SVNSSHAuthentication(userName,Scrambler.descramble(password),-1,false);
+                    return new SVNSSHAuthentication(userName, getPassword(),-1,false);
                 else
-                    return new SVNPasswordAuthentication(userName,Scrambler.descramble(password),false);
+                    return new SVNPasswordAuthentication(userName, getPassword(),false);
+            }
+
+            private String getPassword() {
+                return Scrambler.descramble(Secret.toString(password));
             }
         }
 
@@ -1533,7 +1537,7 @@
              */
             private static final long serialVersionUID = -4649332611621900514L;
             private final String userName;
-            private final String passphrase; // scrambled by base64
+            private final Secret passphrase; // for historical reasons, scrambled by base64 in addition to using 'Secret'
             private final String id;
 
             /**
@@ -1542,7 +1546,7 @@
              */
             public SshPublicKeyCredential(String userName, String passphrase, File keyFile) throws SVNException {
                 this.userName = userName;
-                this.passphrase = Scrambler.scramble(passphrase);
+                this.passphrase = Secret.fromString(Scrambler.scramble(passphrase));
 
                 Random r = new Random();
                 StringBuilder buf = new StringBuilder();
@@ -1613,7 +1617,7 @@
                         } else {
                             privateKey = FileUtils.readFileToString(getKeyFile(),"iso-8859-1");
                         }
-                        return new SVNSSHAuthentication(userName, privateKey.toCharArray(), Scrambler.descramble(passphrase),-1,false);
+                        return new SVNSSHAuthentication(userName, privateKey.toCharArray(), Scrambler.descramble(Secret.toString(passphrase)),-1,false);
                     } catch (IOException e) {
                         throw new SVNException(
                                 SVNErrorMessage.create(SVNErrorCode.AUTHN_CREDS_UNAVAILABLE,"Unable to load private key").initCause(e));
@@ -1635,10 +1639,10 @@
              */
             private static final long serialVersionUID = 5455755079546887446L;
             private final Secret certificate;
-            private final String password; // scrambled by base64
+            private final Secret password; // for historical reasons, scrambled by base64 in addition to using 'Secret'
 
             public SslClientCertificateCredential(File certificate, String password) throws IOException {
-                this.password = Scrambler.scramble(password);
+                this.password = Secret.fromString(Scrambler.scramble(password));
                 this.certificate = Secret.fromString(new String(Base64.encode(FileUtils.readFileToByteArray(certificate))));
             }
 
@@ -1648,7 +1652,7 @@
                     try {
                         SVNSSLAuthentication authentication = new SVNSSLAuthentication(
                                 Base64.decode(certificate.getPlainText().toCharArray()),
-                                Scrambler.descramble(password), false);
+                                Scrambler.descramble(Secret.toString(password)), false);
                         authentication.setCertificatePath("dummy"); // TODO: remove this JENKINS-19175 workaround
                         return authentication;
                     } catch (IOException e) {
```
