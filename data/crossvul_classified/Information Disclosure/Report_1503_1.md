# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 1503_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1503_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 891-932 of the vulnerable file.

            }
            rolesSearch(searchContext, roleDN);
         }
         else
         {
            if (trace) {
               log.trace("Already visited role '" + roleDN + "' ending recursion.");
            }
         }
      }
   }

   protected void traceLdapEnv(Properties env)
   {
      if (trace)
      {
         Properties tmp = new Properties();
         tmp.putAll(env);
         String credentials = tmp.getProperty(Context.SECURITY_CREDENTIALS);
         String bindCredential = tmp.getProperty(BIND_CREDENTIAL);
         if (credentials != null && credentials.length() > 0)
            tmp.setProperty(Context.SECURITY_CREDENTIALS, "***");
         
         if (bindCredential != null && bindCredential.length() > 0)
             tmp.setProperty(BIND_CREDENTIAL, "***");
         
         log.trace("Logging into LDAP server, env=" + tmp.toString());
      }
   }

   protected String canonicalize(String searchResult)
   {
      String result = searchResult;
      int len = searchResult.length();

      if (searchResult.endsWith("\""))
      {
         result = searchResult.substring(0, len - 1) + "," + rolesCtxDN + "\"";
      }
      else
      {
         result = searchResult + "," + rolesCtxDN;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -908,11 +908,14 @@
          tmp.putAll(env);
          String credentials = tmp.getProperty(Context.SECURITY_CREDENTIALS);
          String bindCredential = tmp.getProperty(BIND_CREDENTIAL);
-         if (credentials != null && credentials.length() > 0)
-            tmp.setProperty(Context.SECURITY_CREDENTIALS, "***");
          
-         if (bindCredential != null && bindCredential.length() > 0)
-             tmp.setProperty(BIND_CREDENTIAL, "***");
+         if (credentials != null && credentials.length() > 0) {
+        	 tmp.setProperty(Context.SECURITY_CREDENTIALS, "***");
+         }
+            
+         if (bindCredential != null && bindCredential.length() > 0) {
+        	 tmp.setProperty(BIND_CREDENTIAL, "***");
+         }
          
          log.trace("Logging into LDAP server, env=" + tmp.toString());
       }
```
